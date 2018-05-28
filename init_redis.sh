# install redis script
wget http://download.redis.io/releases/redis-3.2.7.tar.gz
tar xzf redis-3.2.7.tar.gz
cd redis-3.2.7
make
apt-get install tcl
make test
make install