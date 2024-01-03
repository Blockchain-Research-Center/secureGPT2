run:
    make -j && ./bin/main

test:
    make -j
    nohup ./bin/server > server.log 2>&1 &
    sleep 1
    nohup ./bin/client > client.log 2>&1 &
