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
    char *message = compute_post_request(SERVER_IP, LOGIN_PATH, content_type, body_parts, 1, NULL, 0);

    // send request to server
    send_to_server(server_fd, message);

    char *response = receive_from_server(server_fd);
    // check the response and extract the session cookie
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

            printf("SUCCESS: Admin logged in\n");
        }
        else {
            printf("ERROR: Admin login failed\n");
        }
    }

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
    char *message = compute_post_request(SERVER_IP, ADD_USER_PATH, content_type, body_parts, 1, &session_cookie, 1);

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

    char *message = compute_get_request(SERVER_IP, GET_USERS_PATH, NULL, cookies, 1);
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

void handle_logout_admin() {
    if (session_cookie == NULL) {
        printf("ERROR: Admin not logged in\n");
        return;
    }

    // create GET request

    free(session_cookie);
    session_cookie = NULL;
    printf("SUCCESS: Admin logged out\n");
}

void handle_login(int server_fd) {
    if (session_cookie == NULL) {
        printf("ERROR: Admin not logged in\n");
        return;
    }

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
    char *cookies[1] = {session_cookie};

    char *message = compute_post_request(SERVER_IP, USER_LOGIN_PATH, content_type, body_parts, 1, cookies, 1);
    send_to_server(server_fd, message);

    char *response = receive_from_server(server_fd);

    int status_code = 0;
    sscanf(response, "HTTP/1.1 %d", &status_code);

    printf("Response: \n%s\n", response);
    if (status_code == 200) {
        printf("SUCCESS: User logged in\n");
        printf("Response: \n%s\n", response);
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
            handle_logout_admin();
        }
        else if (strcmp(command, "login") == 0) {
            handle_login(server_fd);
        }
        else {
            printf("ERROR: Unknown command\n");
        }

        close_connection(server_fd);
    }

    return 0;
}
