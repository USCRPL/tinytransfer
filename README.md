tinytransfer

run git submodules update --recursive to get pybind and heatshrink installed

activate python venv when modifying (venv forces python 3.9) or specify path to python executable when running cmake list so:

cmake .. -DPYTHON_EXECUTABLE="C:/Path/To/Python3.13/python.exe"
make
