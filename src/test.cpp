#include <pybind11/pybind11.h>

namespace py = pybind11;

int testMe(int x){
    return x+2;
}

PYBIND11_MODULE(cooked, handle){
    handle.doc() = "testing pybind";
    handle.def("test_me", &testMe);
}
