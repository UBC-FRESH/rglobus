## OAUTH

OAUTH2 <- "https://auth.globus.org/v2/oauth2"

#' @importFrom httr2 oauth_client
client <-
    function()
{
    client_id <- Sys.getenv("GLOBUS_CLIENT_ID", unset = "")
    if (!nzchar(client_id)) {
        client_id <- Sys.getenv("RGLOBUS_CLIENT_ID", unset = "")
    }
    if (!nzchar(client_id)) {
        client_id <- "66ab38b0-4eb9-4751-a474-21f463b9881d"
    }
    oauth_client(
        id = client_id,
        token_url = paste0(OAUTH2, "/token"),
        name = "HuBMAPR"
    )
}

`%||%` <- function(x, y)
{
    if (!is.null(x) && nzchar(x)) {
        x
    } else {
        y
    }
}

token_cache <- new.env(parent = emptyenv())

random_state <- function(n = 32)
{
    alphabet <- c(letters, LETTERS, as.character(0:9))
    paste(sample(alphabet, n, replace = TRUE), collapse = "")
}

parse_query_string <- function(x)
{
    if (!nzchar(x)) {
        return(list())
    }
    parts <- strsplit(x, "&", fixed = TRUE)[[1]]
    out <- vector("list", length(parts))
    nms <- character(length(parts))
    for (i in seq_along(parts)) {
        kv <- strsplit(parts[[i]], "=", fixed = TRUE)[[1]]
        key <- utils::URLdecode(kv[[1]])
        val <- if (length(kv) > 1) {
            utils::URLdecode(paste(kv[-1], collapse = "="))
        } else {
            ""
        }
        nms[[i]] <- key
        out[[i]] <- val
    }
    names(out) <- nms
    out
}

extract_callback_params <- function(input, expected_state)
{
    input <- trimws(input)

    if (grepl("^https?://", input)) {
        query <- sub("^[^?]*\\??", "", input)
        query <- sub("#.*$", "", query)
        params <- parse_query_string(query)
        code <- params[["code"]]
        state <- params[["state"]]
    } else {
        code <- input
        state <- ""
    }

    if (!nzchar(code)) {
        stop("No authorization code was provided.", call. = FALSE)
    }

    if (nzchar(state) && !identical(state, expected_state)) {
        message(
            "State mismatch.\n",
            "Expected: ", expected_state, "\n",
            "Received: ", state
        )
        confirm <- readline("Proceed anyway? [y/N]: ")
        if (!identical(tolower(trimws(confirm)), "y")) {
            stop("Aborted due to state mismatch.", call. = FALSE)
        }
    }

    list(code = code, state = state)
}

hosted_pkce_token <- function(client, scope, redirect_uri)
{
    pkce <- httr2::oauth_flow_auth_code_pkce()
    pkce_challenge <- pkce$challenge %||% pkce$code_challenge
    pkce_method <- pkce$method %||% pkce$code_challenge_method %||% "S256"
    pkce_verifier <- pkce$verifier %||% pkce$code_verifier
    if (!nzchar(pkce_verifier)) {
        stop("PKCE verifier was not generated.", call. = FALSE)
    }

    state <- random_state()
    auth_request_url <- httr2::oauth_flow_auth_code_url(
        client = client,
        auth_url = paste0(OAUTH2, "/authorize"),
        redirect_uri = redirect_uri,
        scope = scope,
        state = state,
        auth_params = list(
            code_challenge = pkce_challenge,
            code_challenge_method = pkce_method,
            access_type = "offline"
        )
    )

    message("\nOpen this URL in your browser and complete login/consent:\n")
    cat(auth_request_url, "\n\n", sep = "")
    message("After approval, paste the full callback URL if possible.")

    callback_input <- ""
    while (!nzchar(callback_input)) {
        callback_input <- readline("Enter authorization code or URL: ")
        callback_input <- trimws(callback_input)
    }
    callback <- extract_callback_params(callback_input, state)

    token_resp <-
        httr2::request(paste0(OAUTH2, "/token")) |>
        httr2::req_method("POST") |>
        httr2::req_body_form(
            grant_type = "authorization_code",
            client_id = client$id,
            code = callback$code,
            code_verifier = pkce_verifier,
            redirect_uri = redirect_uri
        ) |>
        httr2::req_perform()

    if (httr2::resp_status(token_resp) >= 400) {
        stop(
            "Token exchange failed: HTTP ", httr2::resp_status(token_resp), "\n",
            httr2::resp_body_string(token_resp),
            call. = FALSE
        )
    }

    token_body <- httr2::resp_body_json(token_resp, simplifyVector = TRUE)
    token_body$obtained_at <- Sys.time()
    if (!is.null(token_body$expires_in)) {
        token_body$expires_at <- token_body$obtained_at + token_body$expires_in
    }
    token_body
}

get_cached_token <- function(scope)
{
    token <- token_cache[[scope]]
    if (is.null(token)) {
        return(NULL)
    }
    if (is.null(token$expires_at)) {
        return(token)
    }
    if (Sys.time() < (token$expires_at - 60)) {
        return(token)
    }
    NULL
}

is_localhost_redirect <- function(uri)
{
    grepl("^https?://(localhost|127\\.0\\.0\\.1)(:|/|$)", uri)
}

resolve_redirect_uri <- function()
{
    redirect_uri <- Sys.getenv("RGLOBUS_REDIRECT_URI", unset = "")
    if (!nzchar(redirect_uri)) {
        redirect_uri <- Sys.getenv("HTTR2_OAUTH_REDIRECT_URL", unset = "")
    }
    if (!nzchar(redirect_uri)) {
        redirect_uri <- paste0("http://localhost:", httpuv::randomPort())
    }
    redirect_uri
}

hosted_flow_enabled <- function(redirect_uri)
{
    flag <- Sys.getenv("RGLOBUS_HOSTED_AUTH", unset = "")
    if (nzchar(flag)) {
        return(tolower(flag) %in% c("1", "true", "yes", "y"))
    }
    !is_localhost_redirect(redirect_uri)
}

#' @importFrom httr2 req_oauth_auth_code
oauth <-
    function(.req, scope, cache_disk = TRUE)
{
    redirect_uri <- resolve_redirect_uri()
    scope <- if (length(scope) > 1) paste(scope, collapse = " ") else scope
    if (hosted_flow_enabled(redirect_uri)) {
        token <- get_cached_token(scope)
        if (is.null(token)) {
            token <- hosted_pkce_token(client(), scope, redirect_uri)
            token_cache[[scope]] <- token
        }
        httr2::req_auth_bearer_token(.req, token$access_token)
    } else {
        req_oauth_auth_code(
            .req,
            client = client(),
            auth_url = paste0(OAUTH2, "/authorize"),
            scope = scope,
            redirect_uri = redirect_uri,
            cache_disk = cache_disk
        )
    }
}

## TRANSFER

TRANSFER <- "https://transfer.api.globus.org/v0.10"

TRANSFER_SCOPE <- paste(
    "urn:globus:auth:scope:transfer.api.globus.org:all",
    "offline_access"
)

HUBMAP_COLLECTION <-
    ## from the web interface, looking for details on 'HuBMAP Public'
    ## collection.  Are all datasets under 'HuBMAP Public' ??
    "af603d86-eab9-4eec-bb1d-9d26556741bb"

## Utilities & workflows

#' @importFrom dplyr pull
pull_id <-
    function(.data, id_column)
{
    stopifnot(
        `'.data' must have exactly 1 row` = NROW(.data) == 1L,
        `'.data' must have a column 'id'` = id_column %in% colnames(.data)
    )
    pull(.data, id_column)
}

#' @importFrom httr2 resp_body_string
#'
#' @importFrom rjsoncons j_query
error_body <-
    function(resp)
{
    body <- resp_body_string(resp)
    code <- j_query(body, "code", as = "R")
    message <- j_query(body, "message", as = "R")
    extra <-
        if (identical(code, "ConsentRequired")) {
            paste0("\n  ", j_query(body, "required_scopes", as = "R"))
        }
    paste0(
        code, ":\n  ",
        message,
        extra
    )
}

#' @importFrom httr2 request req_url_query req_body_raw req_error
#'     req_perform
req_resp <-
    function(uri, ..., .body = NULL)
{
    req <- request(uri)
    req <- req_url_query(req, ...)
    if (!is.null(.body))
        req <- req_body_raw(req, .body)
    req <- oauth(req, TRANSFER_SCOPE)
    req <- req_error(req, body = error_body)
    req_perform(req)
}

## clean 'list' columns to vectors, if possible
tibble_column_unlist_maybe <-
    function(.x)
{
    ## requirement for unlisting -- 0 or 1 elements in each list
    lengths <- lengths(.x)
    if (!all(lengths) < 2L)
        return(.x)

    result <- rep(NA, length(.x))
    result[lengths == 1] <- unlist(.x)
    result
}

#' @importFrom httr2 resp_body_string
#'
#' @importFrom dplyr bind_rows mutate select everything across where
#'
#' @importFrom rjsoncons j_pivot
resp_as_tibble <-
    function(resp, data_type, all_fields, tbl0)
{
    required_fields <- colnames(tbl0)
    body <- resp_body_string(resp)
    stopifnot(
        `unexpected 'DATA_TYPE' in response` =
            identical(j_query(body, "DATA_TYPE"), data_type)
    )
    tbl <- j_pivot(body, "DATA", as = "tibble")
    if (!NROW(tbl))
        tbl <- tbl0
    tbl <- select(tbl, required_fields, if (all_fields) everything())

    mutate(tbl, across(where(is.list), tibble_column_unlist_maybe))
}
