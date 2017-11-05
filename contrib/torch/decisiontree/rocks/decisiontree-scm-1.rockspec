package = "decisiontree"
version = "scm-1"

source = {
   url = "git://github.com/Twitter/decisiontree",
   tag = "master"
}

description = {
   summary = "Decision trees for Torch by Twitter",
   detailed = [[
   Classification and regression trees (CART).
   Gradients boosted decision trees (GBDT).
   ]],
   homepage = "https://github.com/Twitter/decisiontree",
   license = "BSD"
}

dependencies = {
   "torch >= 7.0",
   "moses >= 1.3.1",
   "xlua >= 1.0",
   "image >= 1.0",
   "luafilesystem >= 1.6.2",
   "sys >= 1.1",
   "paths >= 1.0",
   "ipc >= 1.0",
   "nn >= 1.0"
}

build = {
   type = "command",
   build_command = [[
cmake -E make_directory build;
cd build;
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH="$(LUA_BINDIR)/.." -DCMAKE_INSTALL_PREFIX="$(PREFIX)" -DCMAKE_C_FLAGS=-fPIC -DCMAKE_CXX_FLAGS=-fPIC;
$(MAKE)
   ]],
   install_command = "cd build && $(MAKE) install"
}
