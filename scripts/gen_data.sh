#!/bin/bash

# Output file
output_file="output.csv"

# Header
echo "id,username,email,details" > $output_file

# Generate 1 million values
for i in $(seq 1 1000000)
do
  id=$i
  username="user_$i"
  email="user_$i@example.com"
  details=$(shuf -n1 -e "detail1" "detail2" "detail3" "detail4" "detail5")
  
  echo "$id,$username,$email,$details" >> $output_file
done

echo "CSV file with 1 million records generated: $output_file"
