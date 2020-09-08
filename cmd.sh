#before
#go build

#run the code
for id in {0..7}
do 
(
./optimizePBFT pbft node -id $id
) &
done
wait

#after run the node, run the client
#./optimizePBFT pbft client

#use this command to kill all process
#ps -ef | grep ./optimizePBFT | grep -v grep | awk '{print$2}' | xargs kill -9