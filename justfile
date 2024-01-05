run:
    make -j && ./bin/main

test:
    make -j
    nohup ./bin/client > client.log 2>&1 &
    sleep 1
    ./bin/server
    killall ./bin/client
