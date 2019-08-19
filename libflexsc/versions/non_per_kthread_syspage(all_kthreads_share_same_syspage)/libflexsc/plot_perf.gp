reset
set xlabel 'thread no.'
set ylabel 'time (ns)'
set title 'FlexSC getpid() performance'
set term png enhanced font 'Verdana,10'
set output 'perf_measure.png'
set key right

# set format y '%g' 
set logscale y

file_exists = system("file /tmp/flexSC_logfile_flex.txt /tmp/flexSC_logfile_normal.txt | grep 'No such'")
if (strlen(file_exists)) {system("echo 'Error: either _flex or _normal logfile is not exists'"); exit}

plot [1:][:] \
'/tmp/flexSC_logfile_flex.txt' using 1:2 with points title 'FlexSC',\
'/tmp/flexSC_logfile_normal.txt' using 1:2 with points title 'normal'
