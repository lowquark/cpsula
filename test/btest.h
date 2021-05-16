#ifndef BTEST_H
#define BTEST_H

#if __has_builtin(__builtin_trap)
#define BTEST_ABORT __builtin_trap()
#else
#define BTEST_ABORT abort()
#endif

#define BTEST_PRINTF(...) fprintf(stderr, __VA_ARGS__)

#define BTEST_QUOTE_(_exp_) #_exp_
#define BTEST_QUOTE(_exp_) BTEST_QUOTE_(_exp_)

#define BTEST_INT_OP(_a_, _b_, _op_)                                                    \
  do {                                                                                  \
    const intmax_t _BTEST_VAR_A_ = (_a_);                                               \
    const intmax_t _BTEST_VAR_B_ = (_b_);                                               \
    if(!(_BTEST_VAR_A_ _op_ _BTEST_VAR_B_)) {                                           \
      BTEST_PRINTF(                                                                     \
              " #### "__FILE__":"BTEST_QUOTE(__LINE__)": "                              \
              "Test '"#_a_" "#_op_" "#_b_"' failed\n  | "                               \
              #_a_" == %jd\n  | "#_b_" == %jd\n", _BTEST_VAR_A_, _BTEST_VAR_B_);        \
      BTEST_ABORT;                                                                      \
    }                                                                                   \
  } while(0)

#define BTEST_INT_EQ(_a_, _b_) BTEST_INT_OP(_a_, _b_, ==)
#define BTEST_INT_NE(_a_, _b_) BTEST_INT_OP(_a_, _b_, !=)
#define BTEST_INT_LE(_a_, _b_) BTEST_INT_OP(_a_, _b_, <=)
#define BTEST_INT_LT(_a_, _b_) BTEST_INT_OP(_a_, _b_, <)
#define BTEST_INT_GE(_a_, _b_) BTEST_INT_OP(_a_, _b_, >=)
#define BTEST_INT_GT(_a_, _b_) BTEST_INT_OP(_a_, _b_, >)

#define BTEST_UINT_OP(_a_, _b_, _op_)                                                   \
  do {                                                                                  \
    const uintmax_t _BTEST_VAR_A_ = (_a_);                                              \
    const uintmax_t _BTEST_VAR_B_ = (_b_);                                              \
    if(!(_BTEST_VAR_A_ _op_ _BTEST_VAR_B_)) {                                           \
      BTEST_PRINTF(                                                                     \
              __FILE__":"BTEST_QUOTE(__LINE__)": "                                      \
              "Test '"#_a_" "#_op_" "#_b_"' failed\n  | "                               \
              #_a_" == %ju\n  | "#_b_" == %ju\n", _BTEST_VAR_A_, _BTEST_VAR_B_);        \
      BTEST_ABORT;                                                                      \
    }                                                                                   \
  } while(0)

#define BTEST_UINT_EQ(_a_, _b_) BTEST_UINT_OP(_a_, _b_, ==)
#define BTEST_UINT_NE(_a_, _b_) BTEST_UINT_OP(_a_, _b_, !=)
#define BTEST_UINT_LE(_a_, _b_) BTEST_UINT_OP(_a_, _b_, <=)
#define BTEST_UINT_LT(_a_, _b_) BTEST_UINT_OP(_a_, _b_, <)
#define BTEST_UINT_GE(_a_, _b_) BTEST_UINT_OP(_a_, _b_, >=)
#define BTEST_UINT_GT(_a_, _b_) BTEST_UINT_OP(_a_, _b_, >)

#define BTEST_STR_EQ(_a_, _b_)                                                          \
  do {                                                                                  \
    const char * _BTEST_VAR_A_ = (_a_);                                                 \
    const char * _BTEST_VAR_B_ = (_b_);                                                 \
    if(_BTEST_VAR_A_ == NULL && _BTEST_VAR_B_ == NULL) {                                \
      break;                                                                            \
    } else if(_BTEST_VAR_A_ == NULL && _BTEST_VAR_B_ != NULL) {                         \
      BTEST_PRINTF(                                                                     \
              __FILE__":"BTEST_QUOTE(__LINE__)": "                                      \
              "Test '"#_a_" == "#_b_"' failed\n  | "                                    \
              #_a_" == NULL\n  | "#_b_" == \"%s\"\n", _BTEST_VAR_B_);                   \
      BTEST_ABORT;                                                                      \
    } else if(_BTEST_VAR_A_ != NULL && _BTEST_VAR_B_ == NULL) {                         \
      BTEST_PRINTF(                                                                     \
              __FILE__":"BTEST_QUOTE(__LINE__)": "                                      \
              "Test '"#_a_" == "#_b_"' failed\n  | "                                    \
              #_a_" == \"%s\"\n  | "#_b_" == NULL\n", _BTEST_VAR_A_);                   \
      BTEST_ABORT;                                                                      \
    } else if((_BTEST_VAR_A_ == NULL && _BTEST_VAR_B_ != NULL) ||                       \
       (_BTEST_VAR_A_ != NULL && _BTEST_VAR_B_ == NULL) ||                              \
       (strcmp(_BTEST_VAR_A_, _BTEST_VAR_B_) != 0)) {                                   \
      BTEST_PRINTF(                                                                     \
              __FILE__":"BTEST_QUOTE(__LINE__)": "                                      \
              "Test '"#_a_" == "#_b_"' failed\n  | "                                    \
              #_a_" == \"%s\"\n  | "#_b_" == \"%s\"\n", _BTEST_VAR_A_, _BTEST_VAR_B_);  \
      BTEST_ABORT;                                                                      \
    }                                                                                   \
  } while(0)

#define BTEST_PTR_OP(_a_, _b_, _op_)                                                    \
  do {                                                                                  \
    const void * _BTEST_VAR_A_ = (_a_);                                                 \
    const void * _BTEST_VAR_B_ = (_b_);                                                 \
    if(!(_BTEST_VAR_A_ _op_ _BTEST_VAR_B_)) {                                           \
      BTEST_PRINTF(                                                                     \
              __FILE__":"BTEST_QUOTE(__LINE__)": "                                      \
              "Test '"#_a_" "#_op_" "#_b_"' failed\n  | "                               \
              #_a_" == %p\n  | "#_b_" == %p\n", _BTEST_VAR_A_, _BTEST_VAR_B_);          \
      BTEST_ABORT;                                                                      \
    }                                                                                   \
  } while(0)

#define BTEST_PTR_EQ(_a_, _b_) BTEST_PTR_OP(_a_, _b_, ==)
#define BTEST_PTR_NE(_a_, _b_) BTEST_PTR_OP(_a_, _b_, !=)

#define BTEST_PTR_NULL(_a_, _b_) BTEST_PTR_OP(_a_, NULL, ==)
#define BTEST_PTR_NONNULL(_a_, _b_) BTEST_PTR_OP(_a_, NULL, !=)

#endif
