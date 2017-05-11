#ifndef SAFE_ASSERT_H
#define SAFE_ASSERT_H


#include <iostream>

using namespace std;

#undef assert
#define assert(condition) if (!condition) {cerr << "Assertion failed!\n"; exit(EXIT_FAILURE);}


#endif // SAFE_ASSERT_H
