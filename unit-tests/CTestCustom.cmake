
# Remove sep256k1 tests from the list of tests to run
# since they are not part of the application source code

set(CTEST_CUSTOM_TESTS_IGNORE
  noverify_tests
  tests
  exhaustive_tests
)
