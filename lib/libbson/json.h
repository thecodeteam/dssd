/*
 * Copyright 2017 Dell Inc. or its subsidiaries.  All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef	_JSON_H
#define	_JSON_H

#include <bson.h>

#ifdef	__cplusplus
extern "C" {
#endif

extern int32_t json_string_to_utf8(const char *j, char q, char *s, int m);
extern int32_t json_string_from_utf8(char *j, char q, const char *s, int len);
extern int json_parse(bson_t *b, const char **j, char q, off_t d, int a,
    json_parse_cb *cb, void *arg);

#ifdef	__cplusplus
}
#endif

#endif	/* _JSON_H */
