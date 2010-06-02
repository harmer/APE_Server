/*
  Copyright (C) 2006, 2007, 2008, 2009, 2010  Anthony Catel <a.catel@weelya.com>

  This file is part of APE Server.
  APE is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  APE is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with APE ; if not, write to the Free Software Foundation,
  Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
*/

/* http.c */

#include <string.h>

#include "http.h"
#include "sock.h"
#include "main.h"
#include "utils.h"
#include "dns.h"

#define HTTP_PREFIX		"http://"

void process_websocket(ape_socket *co, acetables *g_ape)
{
	char *pData;
	ape_buffer *buffer = &co->buffer_in;
	websocket_state *websocket = co->parser.data;
	ape_parser *parser = &co->parser;
	
	char *data = pData = &buffer->data[websocket->offset];
	
	if (buffer->length == 0 || parser->ready == 1) {
		return;
	}
	
	if (buffer->length > 502400) {
		shutdown(co->fd, 2);
		return;
	}

	data[buffer->length - websocket->offset] = '\0';
	
	if (*data == '\0') {
		data = &data[1];
	}

	while(data++ != &buffer->data[buffer->length]) {
	
		if ((unsigned char)*data == 0xFF) {
			*data = '\0';
			
			websocket->data = &pData[1];
			
			parser->onready(parser, g_ape);

			websocket->offset += (data - pData)+1;
			
			if (websocket->offset == buffer->length) {
				parser->ready = -1;
				buffer->length = 0;
				websocket->offset = 0;
				
				return;
			}
			
			break;
		}
	}
	
	if (websocket->offset != buffer->length && data != &buffer->data[buffer->length+1]) {
		process_websocket(co, g_ape);
	}
}

/* Just a lightweight http request processor */
void process_http(ape_socket *co, acetables *g_ape)
{
	ape_buffer *buffer = &co->buffer_in;
	http_state *http = co->parser.data;
	ape_parser *parser = &co->parser;
	
	char *data = buffer->data;
	int pos, read, p = 0;
	
	if (buffer->length > MAX_CONTENT_LENGTH) {
		http->error = 1;
		shutdown(co->fd, 2);
		return;
	}

	if (buffer->length == 0) {
		return;
	}

	/* Update the address of http->data and http->uri if buffer->data has changed (realloc) */
	if (http->buffer_addr != NULL && buffer->data != http->buffer_addr) {
		http->data = &buffer->data[(void *)http->data - (void *)http->buffer_addr];
		http->uri = &buffer->data[(void *)http->uri - (void *)http->buffer_addr];
		http->buffer_addr = buffer->data;
	}
	
	/* Setting guardians for seol_ng function */
	/* This will be erased by the next read()'ing loop */
	strncpy (&data[buffer->length], "\0\n\0\n\0\n\0\n", 8);

	/* Processing "loop" - ugly implementation with goto, but very fast */
start:
	data = &buffer->data[http->pos];

	if (*data == '\0') {
		return;
	}

	switch (http->step) {

		case 0:
			pos = seol_ng(data) + 1;

			/* is it a guardian? */
			if (pos > 1 && data[pos - 2] == '\0') {
				return;
			}
			
			/* TODO : endian on 64-bit */
			switch (*(unsigned int *)data & 0xffffffff) {
				case 542393671: /* GET + space */
				case 1195725856:
					http->type = HTTP_GET;
					p = 4;
					break;
				case 1414745936: /* POST */
				case 1347375956:
					http->type = HTTP_POST;
					p = 5;
					break;
				default:
					http->error = 1;
					shutdown(co->fd, 2);
					return;
			}
			
			if (data[p] != '/') {
				http->error = 1;
				shutdown(co->fd, 2);
				return;

			} else {
				int i = p;
				while (p++) {
					switch(data[p]) {
						case ' ':
							http->pos = pos;
							http->step = 1;
							http->uri = &data[i];
							http->buffer_addr = buffer->data;
							data[p] = '\0';
							goto start;
						case '?':
							if (data[p+1] != ' ' && data[p+1] != '\r' && data[p+1] != '\n') {
								http->buffer_addr = buffer->data;
								http->data = &data[p+1];
							}
							break; // switch
						case '\r':
						case '\n':
						case '\0':
							http->error = 1;
							shutdown(co->fd, 2);
							return;
					}
				}
			}

		case 1:
			pos = seol_ng(data) + 1;

			/* is it a guardian? */
			if (pos > 1 && data[pos - 2] == '\0') {
				return;
			}

			if (pos == 1 || (pos == 2 && *data == '\r')) {
				if (http->type == HTTP_GET) {
					/* Ok, at this point we have a blank line. Ready for GET */
					buffer->data[http->pos] = '\0';
					parser->ready = 1;
					urldecode(http->uri);

					parser->onready(parser, g_ape);
					parser->ready = -1;
					buffer->length = 0;
					return;
				} else {
					/* Content-Length is mandatory in case of POST */
					if (http->contentlength <= 0) {
						http->error = 1;
						shutdown(co->fd, 2);
						return;
					} else {
						http->buffer_addr = buffer->data; // save the addr
						http->data = &buffer->data[http->pos+(pos)];
						http->step = 2;
					}
				}
			} else {
				data[pos - 1] = '\0';
				if (data[pos - 2] == '\r') {
					data[pos - 2] = '\0';
				}

				/* Looking for Host header */
				if (http->host == NULL && strncmp(data, "Host: ", 6) == 0) {
					http->host = &data[6];
				} else if (http->type == HTTP_GET) {

					/* Looking for Origin header (for WebSockets Handshake) */
					if (http->origin == NULL && strncmp(data, "Origin: ", 8) == 0) {
						http->origin = &data[8];
					}
				} else {

					/* Looking for Content-Length header */
					if (http->contentlength <= 0 && pos <= 25 && strncmp("Content-Length: ", data, 16) == 0) {
						int cl = atoi(&data[16]);

						/* Content-length can't be negative... */
						if (cl < 1 || cl > MAX_CONTENT_LENGTH) {
							http->error = 1;
							shutdown(co->fd, 2);
							return;
						}
						/* At this time we are ready to read "cl" bytes contents */
						http->contentlength = cl;
					}
				}
			}

			http->pos += pos;
			goto start;

		case 2:
			read = buffer->length - http->pos; // data length
			http->pos += read;
			http->read += read;
			
			if (http->read >= http->contentlength) {

				parser->ready = 1;
				urldecode(http->uri);
				/* no more than content-length */
				buffer->data[http->pos - (http->read - http->contentlength)] = '\0';
				
				parser->onready(parser, g_ape);
				parser->ready = -1;
				buffer->length = 0;
			}

	} // step switch
}

int http_send_headers(http_headers_response *headers, const char *default_h, unsigned int default_len, ape_socket *client, acetables *g_ape)
{
	char code[4];
	int finish = 1;
	struct _http_headers_fields *fields;
	//HTTP/1.1 200 OK\r\n
	
	if (headers == NULL) {
		finish &= sendbin(client->fd, (char *)default_h, default_len, 0, g_ape);
	} else {
		/* We have a lot of write syscall here. TODO : use of writev */
		itos(headers->code, code, 4);
		finish &= sendbin(client->fd, "HTTP/1.1 ", 9, 0, g_ape);
		finish &= sendbin(client->fd, code, 3, 0, g_ape);
		finish &= sendbin(client->fd, " ", 1, 0, g_ape);
		finish &= sendbin(client->fd, headers->detail.val, headers->detail.len, 0, g_ape);
		finish &= sendbin(client->fd, "\r\n", 2, 0, g_ape);
	
		for (fields = headers->fields; fields != NULL; fields = fields->next) {
			finish &= sendbin(client->fd, fields->key.val, fields->key.len, 0, g_ape);
			finish &= sendbin(client->fd, ": ", 2, 0, g_ape);
			finish &= sendbin(client->fd, fields->value.val, fields->value.len, 0, g_ape);
			finish &= sendbin(client->fd, "\r\n", 2, 0, g_ape);
		
			fields = fields->next;
		}
	
		finish &= sendbin(client->fd, "\r\n", 2, 0, g_ape);
	}
	
	return finish;
}

void http_headers_free(http_headers_response *headers)
{
	struct _http_headers_fields *fields;
	
	if (headers == NULL) {
		return;
	}
	
	fields = headers->fields;
	
	while(fields != NULL) {
		struct _http_headers_fields *tmpfields = fields->next;
		
		free(fields->value.val);
		
		free(fields);
		fields = tmpfields;
	}
	free(headers);
}

