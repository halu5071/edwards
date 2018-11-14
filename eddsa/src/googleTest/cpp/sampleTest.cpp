#include "gtest/gtest.h"

#include "point.hpp"

class fixtureName : public :: testing::Test {
  protected:
    virtual void SetUp(){}
    virtual void TearDown(){}
}

TEST_F(fixtureName, testOk) {
  EXPECT_EQ("Hello", hello());
}

int main(int argc, char **argv) {
  ::testing:InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}