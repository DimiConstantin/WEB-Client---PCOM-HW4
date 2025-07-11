#ifndef _REQUESTS_
#define _REQUESTS_

// computes and returns a GET request string (query_params
// and cookies can be set to NULL if not needed)
char *compute_get_request(char *host, char *url, char *query_params,
	char **cookies, int cookies_count, char **headers, int headers_count);

// computes and returns a POST request string (cookies can be NULL if not needed)
char *compute_post_request(char *host, char *url, char* content_type, char **body_data,
	int body_data_fields_count, char **cookies, int cookies_count, char **headers, int headers_count);

// computes and returns a DELETE request string (cookies can be NULL if not needed)
char *compute_delete_request(char *host, char *url, char *query_params,
                            char **cookies, int cookies_count);

// computes and returns a GET request string using JWT token
char *compute_JWT_get_request(char *host, char *url, char *jwt_token);

// builds the JWT header
char *build_jwt_header(char *jwt_token);
#endif
