// { dg-options "-frepo" }

struct A {
  A();
};

A::A() {}

template <typename T>
struct B : public A {
  B() {} // { dg-bogus "" }
};

B<int> b;

int main () {}

// { dg-final { cleanup-repo-files } }
