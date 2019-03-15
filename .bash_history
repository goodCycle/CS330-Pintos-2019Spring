la
ls
sudo apt-get install gcc-4.4
sudo cp /usr/bin/gcc-4.4 /usr/bin/gcc
sudo apt-get install qemu
sudo cp /usr/bin/qemu-system-x86_64 /usr/bin/qemu 
ls
cd ~
ls
wget http://143.248.140.106:3080/bochs-2.6.2.tar.gz
ls
./configure --enable-gdb-stub --with-nogui
make
sudo make install
ls
cd ..
ls
wget http://143.248.140.106:3080/pintos.tar.gz
ls
tar xvf pintos.tar.gz
ls
sudo vi ~/.bashrc
.~/.bashrc
ls
cd pintos
cd src
. ~/.bashrc
cd threads
make
cd build
pintos run alarm-multiple
cd ..
pintos run alarm-multiple
ls
vi ~/pintos/src/utils/pintos
make clean
make
cd build
pintos run alarm-multiple
exit
passwd vok1234
passwd
exit
ls
cd pintos/src/threads/
ls
vi thread.c
cd ..
ls
vi ~/.vimrc
vi src/threads/thread.c
sudo apt-get install ctags
ls
ctags -R
vi ~/.vimrc
ls
vi tags
cd src
l
cd threads/
vi thread.c
cd ../../..
ls
exit
