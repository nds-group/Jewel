# Extract pcap and convert it into txt file
for f in *.pcap
	do
		echo $f
        tshark -r $f -Y 'ip.proto == 6 or ip.proto == 17' -T fields -e frame.time_relative -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e ip.len -e tcp.flags.syn -e tcp.flags.ack -e tcp.flags.push -e tcp.flags.fin -e tcp.flags.reset -e tcp.flags.ecn -e ip.proto -e udp.srcport -e udp.dstport -e eth.src -e eth.dst -e ip.hdr_len -e ip.tos -e ip.ttl -e tcp.window_size_value -e tcp.hdr_len -e udp.length -E separator='|' > $f.txt
	done

# Generate features for joint solution for the first N packet
	do
		echo "Number of packets: $npackets"
		for f in *.txt
			do
				echo $f
				python3 clean_and_label_n_pkts_hybrid.py $f ./csv_files/${f}_${npackets}_pkts.csv $npackets
				# rm $f
			done
	done