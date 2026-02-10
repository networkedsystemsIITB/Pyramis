/**
 * FILE: contexts.h
 * -----------------
 * Generated after an analysis of the processing .dsl file.
 * Contains declarations and definitions of collections
 * referenced in the code.
*/
#ifndef __CONTEXTS_H__
#define __CONTEXTS_H__
#include <vector>
#include <map>
#include <string>

typedef struct user_login_map_struct {
    //std::string name;
    bool login_status;
} user_login_map_struct_t;

std::map<std::string, user_login_map_struct_t> user_login_map {};



#endif