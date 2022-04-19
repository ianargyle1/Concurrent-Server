/*
* friendlist.c - [Starting code for] a web-based friend-graph manager.
*
* Based on:
*  tiny.c - A simple, iterative HTTP/1.0 Web server that uses the
*      GET method to serve static and dynamic content.
*   Tiny Web server
*   Dave O'Hallaron
*   Carnegie Mellon University
*/
#include "csapp.h"

#include "dictionary.h"

#include "more_string.h"

pthread_mutex_t lock;
dictionary_t * friends;

static void * doit_thread(void * con);
static void doit(int fd);
static dictionary_t * read_requesthdrs(rio_t * rp);
static void read_postquery(rio_t * rp, dictionary_t * headers, dictionary_t * d);
static void clienterror(int fd, char * cause, char * errnum,
	char * shortmsg, char * longmsg);
static void print_stringdictionary(dictionary_t * d);
static void serve_request(int fd, char * body);

static void serve_friends(int fd, dictionary_t * query);
static void serve_introduce(int fd, dictionary_t * query);
static void serve_befriend(int fd, dictionary_t * query);
static void serve_unfriend(int fd, dictionary_t * query);

int main(int argc, char ** argv) {
	int listenfd, connfd;
	char hostname[MAXLINE], port[MAXLINE];
	socklen_t clientlen;
	struct sockaddr_storage clientaddr;

	/* Check command line args */
	if (argc != 2) {
		fprintf(stderr, "usage: %s <port>\n", argv[0]);
		exit(1);
	}

	pthread_mutex_init(&lock, NULL);
	listenfd = Open_listenfd(argv[1]);
	friends = (dictionary_t *)make_dictionary(COMPARE_CASE_SENS, free);

	/* Don't kill the server if there's an error, because
	we want to survive errors due to a client. But we
	do want to report errors. */
	exit_on_error(0);

	/* Also, don't stop on broken connections: */
	Signal(SIGPIPE, SIG_IGN);

	while (1) {
		clientlen = sizeof(clientaddr);
		connfd = Accept(listenfd, (SA *)& clientaddr, &clientlen);
		if (connfd >= 0) {
			Getnameinfo((SA *)& clientaddr, clientlen, hostname, MAXLINE,
				port, MAXLINE, 0);
			printf("Accepted connection from (%s, %s)\n", hostname, port);
			int * con = malloc(sizeof(int));
			*con = connfd;
			pthread_t thread;
			Pthread_create(&thread, NULL, doit_thread, con);
			Pthread_detach(thread);
		}
	}
}

/*
* doit - handle one HTTP request/response transaction
*/
void doit(int fd) {
	char buf[MAXLINE], *method, *uri, *version;
	rio_t rio;
	dictionary_t * headers, *query;

	/* Read request line and headers */
	Rio_readinitb(&rio, fd);
	if (Rio_readlineb(&rio, buf, MAXLINE) <= 0)
		return;
	printf("%s", buf);

	if (!parse_request_line(buf, &method, &uri, &version)) {
		clienterror(fd, method, "400", "Bad Request",
			"Friendlist did not recognize the request");
	}
	else {
		if (strcasecmp(version, "HTTP/1.0") &&
			strcasecmp(version, "HTTP/1.1")) {
			clienterror(fd, version, "501", "Not Implemented",
				"Friendlist does not implement that version");
		}
		else if (strcasecmp(method, "GET") &&
			strcasecmp(method, "POST")) {
			clienterror(fd, method, "501", "Not Implemented",
				"Friendlist does not implement that method");
		}
		else {
			headers = read_requesthdrs(&rio);

			/* Parse all query arguments into a dictionary */
			query = make_dictionary(COMPARE_CASE_SENS, free);
			parse_uriquery(uri, query);
			if (!strcasecmp(method, "POST"))
				read_postquery(&rio, headers, query);

			/* You'll want to handle different queries here,
			but the intial implementation always returns
			nothing: */

			if (starts_with("/friends", uri)) {
				pthread_mutex_lock(&lock);
				serve_friends(fd, query);
				pthread_mutex_unlock(&lock);
			}
			else if (starts_with("/introduce", uri)) {
				serve_introduce(fd, query);
			}
			else if (starts_with("/befriend", uri)) {
				pthread_mutex_lock(&lock);
				serve_befriend(fd, query);
				pthread_mutex_unlock(&lock);
			}
			else if (starts_with("/unfriend", uri)) {
				pthread_mutex_lock(&lock);
				serve_unfriend(fd, query);
				pthread_mutex_unlock(&lock);
			}

			/* Clean up */
			free_dictionary(query);
			free_dictionary(headers);
		}

		/* Clean up status line */
		free(method);
		free(uri);
		free(version);
	}
}

void * doit_thread(void * con) {
	int c = *(int *)con;
	free(con);
	doit(c);
	Close(c);
	return NULL;
}

/*
* read_requesthdrs - read HTTP request headers
*/
dictionary_t * read_requesthdrs(rio_t * rp) {
	char buf[MAXLINE];
	dictionary_t * d = make_dictionary(COMPARE_CASE_INSENS, free);

	Rio_readlineb(rp, buf, MAXLINE);
	printf("%s", buf);
	while (strcmp(buf, "\r\n")) {
		Rio_readlineb(rp, buf, MAXLINE);
		printf("%s", buf);
		parse_header_line(buf, d);
	}

	return d;
}

void read_postquery(rio_t * rp, dictionary_t * headers, dictionary_t * dest) {
	char * len_str, *type, *buffer;
	int len;

	len_str = dictionary_get(headers, "Content-Length");
	len = (len_str ? atoi(len_str) : 0);

	type = dictionary_get(headers, "Content-Type");

	buffer = malloc(len + 1);
	Rio_readnb(rp, buffer, len);
	buffer[len] = 0;

	if (!strcasecmp(type, "application/x-www-form-urlencoded")) {
		parse_query(buffer, dest);
	}

	free(buffer);
}

static char * ok_header(size_t len,
	const char * content_type) {
	char * len_str, *header;

	header = append_strings("HTTP/1.0 200 OK\r\n",
		"Server: Friendlist Web Server\r\n",
		"Connection: close\r\n",
		"Content-length: ", len_str = to_string(len), "\r\n",
		"Content-type: ", content_type, "\r\n\r\n",
		NULL);

	free(len_str);

	return header;
}

/*
* serve_request - example request handler
*/
static void serve_request(int fd, char * body) {
	char * header;
	size_t len = strlen(body);

	/* Send response headers to client */
	header = ok_header(len, "text/html; charset=utf-8");
	Rio_writen(fd, header, strlen(header));
	printf("Response headers:\n");
	printf("%s", header);

	free(header);

	/* Send response body to client */
	Rio_writen(fd, body, len);
}

static void serve_friends(int fd, dictionary_t * query) {
	char * body;
	char * user = dictionary_get(query, "user");
	dictionary_t * user_friends = dictionary_get(friends, user);

	if (dictionary_count(query) != 1 || !user) {
		clienterror(fd, "GET", "400", "Bad Request", "Invalid request query.");
	}

	if (!user_friends) {
		body = "";
		serve_request(fd, body);
	}
	else {
		const char ** total_friends = dictionary_keys(user_friends);
		body = join_strings(total_friends, '\n');
		serve_request(fd, body);
	}
}

static void serve_introduce(int fd, dictionary_t * query) {
	char * body;

	if (!query || dictionary_count(query) != 4) {
		clienterror(fd, "POST", "400", "Bad Request", "Invalid request query.");
		return;
	}

	char * host = (char *)dictionary_get(query, "host");
	char * port = (char *)dictionary_get(query, "port");
	const char * friend = dictionary_get(query, "friend");
	const char * user = dictionary_get(query, "user");

	if (!user || !host || !port || !friend) {
		clienterror(fd, "POST", "400", "Bad Request", "Invalid request query.");
		return;
	}

	char buf[MAXBUF];
	int con = Open_clientfd(host, port);
	sprintf(buf, "GET /friends?user=%s HTTP/1.1\r\n\r\n", query_encode(friend));
	Rio_writen(con, buf, strlen(buf));
	Shutdown(con, SHUT_WR);
	char send_buf[MAXLINE];
	rio_t rio;
	Rio_readinitb(&rio, con);

	if (Rio_readlineb(&rio, send_buf, MAXLINE) <= 0) {
		clienterror(fd, "POST", "400", "Bad Request", "Invalid request query.");
	}

	char * status, *version, *desc;
	if (!parse_status_line(send_buf, &version, &status, &desc)) {
		clienterror(fd, "GET", "400", "Bad Request", "Invalid request query.");
	}
	else {
		if (strcasecmp(version, "HTTP/1.1") && strcasecmp(version, "HTTP/1.0")) {
			clienterror(fd, version, "501", "Not Implemented",
				"Friendlist does not implement that version");
		}
		else if (strcasecmp(desc, "OK") && strcasecmp(status, "200")) {
			clienterror(fd, status, "501", "Not Implemented",
				"Bad response");
		}
		else {
			dictionary_t * headers = read_requesthdrs(&rio);
			char * len_str = dictionary_get(headers, "Content-length");

			int len = (len_str ? atoi(len_str) : 0);
			char rec_buf[len];
			if (len <= 0) {
				clienterror(fd, "GET", "400", "Bad Request", "Invalid request query.");
			}
			else {
				print_stringdictionary(headers);
				Rio_readnb(&rio, rec_buf, len);
				rec_buf[len] = 0;
				pthread_mutex_lock(&lock);
				dictionary_t * userDic = dictionary_get(friends, user);
				if (!userDic) {
					printf("New Dictionary!\n");
					userDic = make_dictionary(COMPARE_CASE_SENS, NULL);
					dictionary_set(friends, user, userDic);
				}

				char ** newFriends = split_string(rec_buf, '\n');

				for (int i = 0; newFriends[i] != NULL; i++) {
					if (strcmp(newFriends[i], user) == 0)
						continue;

					dictionary_t * newFr = (dictionary_t *)dictionary_get(friends, user);
					if (!newFr) {
						newFr = (dictionary_t *)make_dictionary(COMPARE_CASE_SENS, free);
						dictionary_set(friends, user, newFr);
					}

					if (dictionary_get(newFr, newFriends[i]) == NULL) {
						dictionary_set(newFr, newFriends[i], NULL);
					}

					dictionary_t * newFR = (dictionary_t *)dictionary_get(friends, newFriends[i]);
					if (newFR == NULL) {
						newFR = (dictionary_t *)make_dictionary(COMPARE_CASE_SENS, free);
						dictionary_set(friends, newFriends[i], newFR);
					}

					if (dictionary_get(newFR, user) == NULL) {
						dictionary_set(newFR, user, NULL);
					}
					free(newFriends[i]);
				}
				free(newFriends);

				const char ** frs = dictionary_keys(userDic);

				body = join_strings(frs, '\n');

				pthread_mutex_unlock(&lock);
				serve_request(fd, body);

				free(body);
			}
		}
		free(version);
		free(status);
		free(desc);
	}
	Close(con);
}

/*
* serve_request - example request handler
*/
static void serve_befriend(int fd, dictionary_t * query) {
	char * body;

	if (!query || dictionary_count(query) != 2) {
		clienterror(fd, "POST", "400", "Bad Request", "Invalid request query.");
		return;
	}

	const char * user = (char *)dictionary_get(query, "user");
	if (!user) {
		dictionary_t * newUser = (dictionary_t *)make_dictionary(COMPARE_CASE_SENS, free);
		dictionary_set(friends, user, newUser);
	}

	dictionary_t * users = (dictionary_t *)dictionary_get(friends, user);
	if (!users) {
		users = (dictionary_t *)make_dictionary(COMPARE_CASE_SENS, free);
		dictionary_set(friends, user, users);
	}

	char ** newFriends = split_string((char *)dictionary_get(query, "friends"), '\n');
	if (!newFriends) {
		clienterror(fd, "POST", "400", "Bad Request", "Invalid request query.");
	}

	for (int i = 0; newFriends[i] != NULL; i++) {
		if (strcmp(newFriends[i], user) == 0)
			continue;

		dictionary_t * newFr = (dictionary_t *)dictionary_get(friends, user);
		if (!newFr) {
			newFr = (dictionary_t *)make_dictionary(COMPARE_CASE_SENS, free);
			dictionary_set(friends, user, newFr);
		}

		if (dictionary_get(newFr, newFriends[i]) == NULL) {
			dictionary_set(newFr, newFriends[i], NULL);
		}

		dictionary_t * newFR = (dictionary_t *)dictionary_get(friends, newFriends[i]);
		if (!newFR) {
			newFR = (dictionary_t *)make_dictionary(COMPARE_CASE_SENS, free);
			dictionary_set(friends, newFriends[i], newFR);
		}

		if (dictionary_get(newFR, user) == NULL) {
			dictionary_set(newFR, user, NULL);
		}
	}

	users = (dictionary_t *)dictionary_get(friends, user);
	const char ** frs = dictionary_keys(users);

	body = join_strings(frs, '\n');

	serve_request(fd, body);
}

/*
* serve_request - example request handler
*/
static void serve_unfriend(int fd, dictionary_t * query) {
	char * body;

	if (!query || dictionary_count(query) != 2) {
		clienterror(fd, "POST", "400", "Bad Request", "Invalid request query.");
	}

	const char * user = (char *)dictionary_get(query, "user");
	if (!user) {
		clienterror(fd, "POST", "400", "Bad Request", "Invalid request query.");
	}

	dictionary_t * users = (dictionary_t *)dictionary_get(friends, user);
	if (!users) {
		clienterror(fd, "POST", "400", "Bad Request", "Invalid request query.");
	}

	char ** frst = split_string((char *)dictionary_get(query, "friends"), '\n');
	if (!frst) {
		clienterror(fd, "GET", "400", "Bad Request", "Invalid request query.");
	}

	for (int i = 0; frst[i] != NULL; i++) {
		dictionary_remove(users, frst[i]);
		dictionary_t * friendSet = (dictionary_t *)dictionary_get(friends, frst[i]);
		if (friendSet != NULL) {
			dictionary_remove(friendSet, user);
		}

	}

	users = (dictionary_t *)dictionary_get(friends, user);
	const char ** frs = dictionary_keys(users);

	body = join_strings(frs, '\n');

	serve_request(fd, body);
}

/*
* clienterror - returns an error message to the client
*/
void clienterror(int fd, char * cause, char * errnum,
	char * shortmsg, char * longmsg) {
	size_t len;
	char * header, *body, *len_str;

	body = append_strings("<html><title>Friendlist Error</title>",
		"<body bgcolor="
		"ffffff"
		">\r\n",
		errnum, " ", shortmsg,
		"<p>", longmsg, ": ", cause,
		"<hr><em>Friendlist Server</em>\r\n",
		NULL);
	len = strlen(body);

	/* Print the HTTP response */
	header = append_strings("HTTP/1.0 ", errnum, " ", shortmsg, "\r\n",
		"Content-type: text/html; charset=utf-8\r\n",
		"Content-length: ", len_str = to_string(len), "\r\n\r\n",
		NULL);
	free(len_str);

	Rio_writen(fd, header, strlen(header));
	Rio_writen(fd, body, len);

	free(header);
	free(body);
}

static void print_stringdictionary(dictionary_t * d) {
	int i, count;

	count = dictionary_count(d);
	for (i = 0; i < count; i++) {
		printf("%s=%s\n",
			dictionary_key(d, i),
			(const char *)dictionary_value(d, i));
	}
	printf("\n");
}