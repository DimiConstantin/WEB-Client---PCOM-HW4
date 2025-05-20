#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "parson/parson.h"
#include "helpers.h"
#include "requests.h"
#include "paths.h"

#define SERVER_IP "63.32.125.183"
#define SERVER_PORT 8081
#define INPUT_LEN 1024

char *session_cookie = NULL;
char *JWT_cookie = NULL;

void handle_login_admin(int server_fd) {
    if (session_cookie != NULL) {
        printf("ERROR: An user is already logged in\n");
        return;
    }

    char username[INPUT_LEN];
    char password[INPUT_LEN];

    // read username and password from stdin
    printf("username=");
    fgets(username, INPUT_LEN, stdin);
    remove_trailing_newline(username);
    printf("password=");
    fgets(password, INPUT_LEN, stdin);
    remove_trailing_newline(password);

    // create JSON object for login
    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);
    json_object_set_string(root_object, "username", username);
    json_object_set_string(root_object, "password", password);
    char *json_payload = json_serialize_to_string(root_value);

    // create POST request
    char *content_type = "application/json";
    char *body_parts[1];
    body_parts[0] = json_payload;
    char *message = compute_post_request(SERVER_IP, LOGIN_PATH, content_type, body_parts, 1, NULL, 0, NULL, 0);

    // send request to server
    send_to_server(server_fd, message);

    char *response = receive_from_server(server_fd);
    // check the response and extract the session cookie
    int status_code = 0;
    sscanf(response, "HTTP/1.1 %d", &status_code);

    if (status_code != 200) {
        printf("ERROR: Admin login failed\n");
        free(message);
        json_free_serialized_string(json_payload);
        json_value_free(root_value);
        return;
    }

    char *cookie_hdr = strstr(response, "Set-Cookie: ");
    if (cookie_hdr) {
        char *cookie_start = cookie_hdr + strlen("Set-Cookie: ");
        char *cookie_end = strstr(cookie_start, ";");
        if (cookie_end) {
            size_t cookie_len = cookie_end - cookie_start;
            free(session_cookie);
            session_cookie = malloc(cookie_len + 1);
            strncpy(session_cookie, cookie_start, cookie_len);
            session_cookie[cookie_len] = '\0';
        }
    }

    printf("SUCCESS: Admin logged in\n");

    free(message);
    json_free_serialized_string(json_payload);
    json_value_free(root_value);
}

void handle_add_user(int server_fd) {
    char username[INPUT_LEN];
    char password[INPUT_LEN];

    if (session_cookie == NULL) {
        printf("ERROR: Admin not logged in\n");
        return;
    }

    // read username, password and email from stdin
    printf("username=");
    fgets(username, INPUT_LEN, stdin);
    remove_trailing_newline(username);
    printf("password=");
    fgets(password, INPUT_LEN, stdin);
    remove_trailing_newline(password);

    // create JSON object for adding user
    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);
    json_object_set_string(root_object, "username", username);
    json_object_set_string(root_object, "password", password);
    char *json_payload = json_serialize_to_string(root_value);

    // create POST request
    char *content_type = "application/json";
    char *body_parts[1];
    body_parts[0] = json_payload;
    char *message = compute_post_request(SERVER_IP, ADD_USER_PATH, content_type, body_parts, 1, &session_cookie, 1, NULL, 0);

    send_to_server(server_fd, message);

    char *response = receive_from_server(server_fd);

    int status_code = 0;
    sscanf(response, "HTTP/1.1 %d", &status_code);

    if (status_code == 201) {
        printf("SUCCESS: User added\n");
    }
    else if (status_code == 409) {
        printf("ERROR: User already exists\n");
    }
    else {
        printf("ERROR: Failed to add user\n");
    }

    free(message);
    json_free_serialized_string(json_payload);
    json_value_free(root_value);
}

void handle_get_users(int server_fd) {
    if (session_cookie == NULL) {
        printf("ERROR: Admin not logged in\n");
        return;
    }

    char *cookies[1] = {session_cookie};

    char *message = compute_get_request(SERVER_IP, GET_USERS_PATH, NULL, cookies, 1, NULL, 0);
    send_to_server(server_fd, message);

    char *response = receive_from_server(server_fd);

    int status_code = 0;
    sscanf(response, "HTTP/1.1 %d", &status_code);

    if (status_code != 200) {
        printf("ERROR: Failed to get users\n");
        free(message);
        return;
    }

    char *json_response = basic_extract_json_response(response);
    DIE(!json_response, "Failed to extract JSON response");
    JSON_Value *root_value = json_parse_string(json_response);
    JSON_Object *root_object = json_value_get_object(root_value);
    JSON_Array *users_array = json_object_get_array(root_object, "users");
    size_t user_count = json_array_get_count(users_array);

    printf("SUCCESS: Users:\n");
    for (size_t i = 0; i < user_count; i++) {
        JSON_Object *user_object = json_array_get_object(users_array, i);
        int id = json_object_get_number(user_object, "id");
        const char *username = json_object_get_string(user_object, "username");
        const char *password = json_object_get_string(user_object, "password");
        printf("#%d %s:%s\n", id, username, password);
    }
    json_value_free(root_value);
    free(message);
}

void handle_delete_user(int server_fd) {
    if (session_cookie == NULL) {
        printf("ERROR: Admin not logged in\n");
        return;
    }

    char username[INPUT_LEN];
    printf("username=");
    fgets(username, INPUT_LEN, stdin);
    remove_trailing_newline(username);

    // create DELETE request
    char *url = malloc(strlen(DELETE_USER_PATH) + strlen(username) + 1);
    snprintf(url, INPUT_LEN, "%s%s", DELETE_USER_PATH, username);

    char *cookies[1] = {session_cookie};
    char *message = compute_delete_request(SERVER_IP, url, NULL, cookies, 1);

    send_to_server(server_fd, message);
    char *response = receive_from_server(server_fd);

    int status_code = 0;
    sscanf(response, "HTTP/1.1 %d", &status_code);

    if (status_code == 200) {
        printf("SUCCESS: User deleted\n");
    }
    else if (status_code == 404) {
        printf("ERROR: User not found\n");
    }
    else {
        printf("ERROR: Failed to delete user\n");
    }
}

void handle_logout_admin(int server_fd) {
    if (session_cookie == NULL) {
        printf("ERROR: Admin not logged in\n");
        return;
    }

    // create GET request
    char *cookies[1] = {session_cookie};
    char *message = compute_get_request(SERVER_IP, LOGOUT_ADMIN, NULL, cookies, 1, NULL, 0);
    send_to_server(server_fd, message);

    char *response = receive_from_server(server_fd);

    int status_code = 0;
    sscanf(response, "HTTP/1.1 %d", &status_code);

    if (status_code != 200) {
        printf("ERROR: Failed to logout admin\n");
        free(message);
        return;
    }

    free(session_cookie);
    free(message);
    session_cookie = NULL;
    printf("SUCCESS: Admin logged out\n");
}

void handle_login(int server_fd) {
    char admin_username[INPUT_LEN];
    char password[INPUT_LEN];
    char username[INPUT_LEN];

    printf("admin_username=");
    fgets(admin_username, INPUT_LEN, stdin);
    remove_trailing_newline(admin_username);

    printf("username=");
    fgets(username, INPUT_LEN, stdin);
    remove_trailing_newline(username);

    printf("password=");
    fgets(password, INPUT_LEN, stdin);
    remove_trailing_newline(password);

    // create JSON object for login
    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);
    json_object_set_string(root_object, "admin_username", admin_username);
    json_object_set_string(root_object, "username", username);
    json_object_set_string(root_object, "password", password);
    char *json_payload = json_serialize_to_string(root_value);

    // create POST request
    char *content_type = "application/json";
    char *body_parts[1] = {json_payload};

    char *message = compute_post_request(SERVER_IP, USER_LOGIN_PATH, content_type, body_parts, 1, NULL, 0, NULL, 0);
    send_to_server(server_fd, message);

    char *response = receive_from_server(server_fd);
    int status_code = 0;
    sscanf(response, "HTTP/1.1 %d", &status_code);

    if (status_code == 200) {
        printf("SUCCESS: User logged in\n");

        char *cookie_hdr = strstr(response, "Set-Cookie: ");
        if (cookie_hdr) {
            char *cookie_start = cookie_hdr + strlen("Set-Cookie: ");
            char *cookie_end = strstr(cookie_start, ";");
            if (cookie_end) {
                size_t cookie_len = cookie_end - cookie_start;
                free(session_cookie);
                session_cookie = malloc(cookie_len + 1);
                strncpy(session_cookie, cookie_start, cookie_len);
                session_cookie[cookie_len] = '\0';
            }
        }
    }
    else if (status_code == 403) {
        printf("ERROR: Invalid credentials\n");
    }
    else {
        printf("ERROR: Failed to login\n");
    }
}

void handle_get_access(int server_fd) {
    if (session_cookie == NULL) {
        printf("ERROR: User not logged in\n");
        return;
    }

    char *cookies[1] = {session_cookie};
    char *message = compute_get_request(SERVER_IP, GET_ACCESS_PATH, NULL, cookies, 1, NULL, 0);

    send_to_server(server_fd, message);

    char *response = receive_from_server(server_fd);

    int status_code = 0;
    sscanf(response, "HTTP/1.1 %d", &status_code);
    if (status_code != 200) {
        printf("ERROR: Failed to get access\n");
        free(message);
        return;
    }

    char *token_hdr = basic_extract_json_response(response);
    JSON_Value *root_value = json_parse_string(token_hdr);
    JSON_Object *root_object = json_value_get_object(root_value);
    const char *token = json_object_get_string(root_object, "token");
    
    JWT_cookie = malloc(strlen(token) + 1);
    strcpy(JWT_cookie, token);

    printf("SUCCESS: Access granted\n");
}

void handle_logout(int server_fd) {
    if (session_cookie == NULL) {
        printf("ERROR: User not logged in\n");
        return;
    }

    char *cookies[1] = {session_cookie};
    char *message = compute_get_request(SERVER_IP, USER_LOGOUT_PATH, NULL, cookies, 1, NULL, 0);
    send_to_server(server_fd, message);

    char *response = receive_from_server(server_fd);
    int status_code = 0;
    sscanf(response, "HTTP/1.1 %d", &status_code);

    if (status_code != 200) {
        printf("ERROR: Failed to logout\n");
        free(message);
        return;
    }

    free(session_cookie);
    free(JWT_cookie);

    session_cookie = NULL;
    JWT_cookie = NULL;

    printf("SUCCESS: User logged out\n");
}

void handle_get_movies(int server_fd) {
    if (session_cookie == NULL) {
        printf("ERROR: User not logged in\n");
        return;
    }

    if (JWT_cookie == NULL) {
        printf("ERROR: User access is not granted\n");
        return;
    }

    char *jwt_header = build_jwt_header(JWT_cookie);
    char *headers[1] = {jwt_header};

    char *message = compute_get_request(SERVER_IP, GET_MOVIES_PATH, NULL, NULL, 0, headers, 1);
    send_to_server(server_fd, message);

    char *response = receive_from_server(server_fd);

    int status_code = 0;
    sscanf(response, "HTTP/1.1 %d", &status_code);

    if (status_code != 200) {
        printf("ERROR: Failed to get movies\n");
        free(message);
        return;
    }

    char *json_response = basic_extract_json_response(response);
    JSON_Value *root_value = json_parse_string(json_response);
    JSON_Object *root_object = json_value_get_object(root_value);
    JSON_Array *movies_array = json_object_get_array(root_object, "movies");
    size_t movie_count = json_array_get_count(movies_array);

    printf("SUCCESS: Movies:\n");
    for (size_t i = 0; i < movie_count; i++) {
        JSON_Object *movie_object = json_array_get_object(movies_array, i);
        const char *title = json_object_get_string(movie_object, "title");
        const int id = json_object_get_number(movie_object, "id");
        printf("#%d %s\n", id, title);
    }

    json_value_free(root_value);
    free(message);
}

void handle_get_movie(int server_fd) {
    if (session_cookie == NULL) {
        printf("ERROR: User not logged in\n");
        return;
    }

    if (JWT_cookie == NULL) {
        printf("ERROR: User access is not granted\n");
        return;
    }

    char id[INPUT_LEN];
    printf("id=");
    fgets(id, INPUT_LEN, stdin);
    remove_trailing_newline(id);

    // create GET request
    int len = strlen(GET_MOVIE_PATH) + strlen(id) + 1;
    char *url = malloc(len);
    snprintf(url, len, "%s%s", GET_MOVIE_PATH, id);

    char *jwt_header = build_jwt_header(JWT_cookie);
    char *headers[1] = {jwt_header};
    char *message = compute_get_request(SERVER_IP, url, NULL, NULL, 0, headers, 1);
    send_to_server(server_fd, message);

    char *response = receive_from_server(server_fd);

    int status_code = 0;
    sscanf(response, "HTTP/1.1 %d", &status_code);

    if (status_code == 404) {
        printf("ERROR: Movie not found\n");
        free(message);
        free(url);
        return;
    }
    else if (status_code != 200) {
        printf("ERROR: Failed to get movie\n");
        free(message);
        free(url);
        return;
    }

    printf("SUCCESS: Movie details:\n");

    char *json_response = basic_extract_json_response(response);
    JSON_Value *root_value = json_parse_string(json_response);
    JSON_Object *root_object = json_value_get_object(root_value);
    const char *title = json_object_get_string(root_object, "title");
    const int year = json_object_get_number(root_object, "year");
    const char *description = json_object_get_string(root_object, "description");
    const char *rating = json_object_get_string(root_object, "rating");

    printf("title: %s\n", title);
    printf("year: %d\n", year);
    printf("description: %s\n", description);
    printf("rating: %.1f\n", atof(rating));

    json_value_free(root_value);
    free(message);
    free(url);
    free(response);

    return;
}

void handle_add_movie(int server_fd) {
    if (session_cookie == NULL) {
        printf("ERROR: User not logged in\n");
        return;
    }

    if (JWT_cookie == NULL) {
        printf("ERROR: User access is not granted\n");
        return;
    }

    char title[INPUT_LEN];
    char year[INPUT_LEN];
    char description[INPUT_LEN];
    char rating[INPUT_LEN];

    // read movie details from stdin
    printf("title=");
    fgets(title, INPUT_LEN, stdin);
    remove_trailing_newline(title);
    printf("year=");
    fgets(year, INPUT_LEN, stdin);
    remove_trailing_newline(year);
    printf("description=");
    fgets(description, INPUT_LEN, stdin);
    remove_trailing_newline(description);
    printf("rating=");
    fgets(rating, INPUT_LEN, stdin);
    remove_trailing_newline(rating);

    // create JSON object for adding movie
    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);
    json_object_set_string(root_object, "title", title);
    json_object_set_number(root_object, "year", atoi(year));
    json_object_set_string(root_object, "description", description);
    json_object_set_number(root_object, "rating", atof(rating));
    
    char *json_payload = json_serialize_to_string(root_value);

    // create POST request
    char *content_type = "application/json";
    char *body_parts[1];
    body_parts[0] = json_payload;
    
    char *jwt_header = build_jwt_header(JWT_cookie);
    char *headers[1] = {jwt_header};

    char *message = compute_post_request(SERVER_IP, GET_MOVIES_PATH, content_type, body_parts, 1, NULL, 0, headers, 1);

    send_to_server(server_fd, message);

    char *response = receive_from_server(server_fd);

    int status_code = 0;
    sscanf(response, "HTTP/1.1 %d", &status_code);

    if (status_code == 201) {
        printf("SUCCESS: Movie added\n");
        free(message);
        free(json_payload);
        json_value_free(root_value);
        return;
    }
}

int main() {
    char input[INPUT_LEN];

    while (1) {
        int server_fd = open_connection(SERVER_IP, SERVER_PORT, AF_INET, SOCK_STREAM, 0);
        DIE(server_fd < 0, "socket/connection failed");

        fgets(input, INPUT_LEN, stdin);

        char *command = remove_trailing_newline(input);

        if (strcmp(command, "exit") == 0) {
            close_connection(server_fd);
            break;
        }
        else if (strcmp(command, "login_admin") == 0) {
            handle_login_admin(server_fd);
        }
        else if (strcmp(command, "add_user") == 0) {
            handle_add_user(server_fd);
        }
        else if (strcmp(command, "get_users") == 0) {
            handle_get_users(server_fd);
        }
        else if (strcmp(command, "delete_user") == 0) {
            handle_delete_user(server_fd);
        }
        else if (strcmp(command, "logout_admin") == 0) {
            handle_logout_admin(server_fd);
        }
        else if (strcmp(command, "login") == 0) {
            handle_login(server_fd);
        }
        else if (strcmp(command, "get_access") == 0) {
            handle_get_access(server_fd);
        }
        else if (strcmp(command, "logout") == 0) {
            handle_logout(server_fd);
        }
        else if (strcmp(command, "get_movies") == 0) {
            handle_get_movies(server_fd);
        }
        else if (strcmp(command, "get_movie") == 0) {
            handle_get_movie(server_fd);
        }
        else if (strcmp(command, "add_movie") == 0) {
            handle_add_movie(server_fd);
        }
        else {
            printf("ERROR: Unknown command\n");
        }

        close_connection(server_fd);
    }

    return 0;
}
