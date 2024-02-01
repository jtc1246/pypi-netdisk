#include <cassert>
#include <iostream>
using namespace std;
typedef uint64_t uint64;
char* a = "hkduvvewbhivewlbijqevkbhvqen";

extern "C" {
void hello_world() {
    cout << "Hello World!" << endl;
}

uint64 plus(uint64 a, uint64 b) {
    return a + b;
}

uint64 minus(uint64 a, uint64 b) {
    return a - b;
}

uint64 times(uint64 a, uint64 b) {
    uint64 c = a * b;
    assert(c / a == b && c % a == 0);
    return c;
}

void content(){
    cout << a << endl;
}
}
