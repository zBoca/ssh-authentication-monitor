
# ===========================================================================================
# ssh-monitor.py
# -------------------------------------------------------------------------------------------
# This program will run 3 test analysis' on 3 different log files. One normal activity log,
# one containing suspicious activity from 1 IP, and one containing suspicious activity from
# multiple IPs. It goes through each log, searches it for failed password submissions, and
# checks how many happened within 60 second time windows. It then classifies them on their
# severity, and makes an incident report if necessary.
# ===========================================================================================



import re
from collections import defaultdict
from datetime import datetime

# Log File
normal_log_file = "sample_logs/normal_ssh_auth.log"
suspicious_single_log_file = "sample_logs/suspicious_single_ssh_auth.log"
suspicious_multiple_log_file = "sample_logs/suspicious_multiple_ssh_auth.log"

# Thresholds
time_window_seconds = 60

# Matching for: 'Failed password for soc-test from *IP* port *PORT*'
log_in_fail_pattern = re.compile(
	r"Failed password for (\S+) from ([\d.]+) port (\d+)"
)

def run_analysis( log_file ):
	events = []
	incidents = []

	# Open the log file
	with open( log_file, "r" ) as file:
		for line in file:
			# Check if the current line matches the pattern
			match = log_in_fail_pattern.search( line )

			if match:
				# Get info about who tried to sign in from the log
				username = match.group( 1 )
				source_ip = match.group( 2 )
				source_port = match.group( 3 )

				# Extract the timestamp from the beginning of the log
				timestamp_match = re.match(
					r"(\w+ \d+ \d+:\d+:\d+)",
					line
				)

				# Check if the timestamp was found
				if timestamp_match:
					timestamp = datetime.strptime(
							f"{datetime.now().year} {timestamp_match.group( 1 )}",
							"%Y %b %d %H:%M:%S"
							)
					events.append( {
						"timestamp"  : timestamp,
						"username"   : username,
						"source_ip"  : source_ip,
						"source_port": source_port
						})

	# Display the results header
	print( "\n"                                                           )
	print( "============================================================" )
	print( "SSH Authentication Monitor"                                   )
	print( "============================================================" )

	print( "\nAnalyzed", len(events), "failed SSH authentication events." )

	# Group the events by their source_ip
	events_by_ip = defaultdict( list )

	for event in events:
		events_by_ip[ event[ "source_ip" ] ].append( event )

	# Analyze the source_ip variables
	for ip, ip_events in events_by_ip.items():
		print( "\nSource IP:", ip )
		print( "Failed attempts:", len( ip_events ) )

		# Check for repeated failures within the detection window
		for i in range( len(ip_events) ):
			window_start = ip_events[i][ "timestamp" ]
			attempts = 0

			for j in range( i, len( ip_events ) ):
				time_difference = (
					ip_events[j][ "timestamp" ] - window_start
				).total_seconds()

				if time_difference <= time_window_seconds:
					attempts += 1
				else:
					break

			# Find the severity level
			if attempts >= 10:
				severity = "CRITICAL"
			elif attempts >= 6:
				severity = "HIGH"
			elif attempts >= 3:
				severity = "MEDIUM"
			else:
				severity = "LOW"

			# Display an alert if there is more failed login attempts than the threshold
			if attempts >= 3:
				print( "\n[ ALERT ] Possible SSH brute-force attack" )
				print( "Source IP:", ip )
				print( "Failed attempts:", attempts )
				print( "Severity:", severity )
				print( "Detection window:", time_window_seconds, "seconds" )
				incidents.append( {
					"ip":ip,
					"attempts":attempts,
					"severity":severity
					} )
				break

	# Write the incident report
	if incidents:
		with open( "incidents/incident_report_"+ datetime.now().strftime('%Y%m%d_%H%M%S') + ".txt", "w" ) as file:
			file.write( "\nSSH SECURITY INCIDENT REPORT\n" )
			file.write( "==============================\n\n" )
			file.write( f"Generated on: {datetime.now().strftime( '%Y-%m-%d %H:%M:%S' )}\n" )
			file.write( f"Incidents Detected: { len(incidents) }\n\n" )

			for number, incident in enumerate( incidents, 1 ):
				file.write( f"INCIDENT #{number}\n")
				file.write( "------------------\n" )
				file.write( f"Source IP: {incident['ip']}\n" )
				file.write( f"Failed Attempts: {incident['attempts']}\n" )
				file.write( "Detection Window: 60 seconds\n" )
				file.write( f"Severity: {incident['severity']}\n" )
				file.write( "Detection Type: SSH Brute-Force Attempt\n\n" )

			file.write( "Recommended Actions:\n" )
			file.write(
				"Investigate source IPs and review authentication logs for additional suspicious activity.\n\n"
				)
		print( "\nIncident report created\n" )

	# Diplay the results footer
	print( "\n" )
	print( "============================================================" )
	print( "Analysis complete."                                           )
	print( "============================================================" )
	print( "\n" )

print( "\nTest Case 1 -- Normal Activity\n" )
run_analysis( normal_log_file )
print( "\nTest Case 2 -- Single Source Brute Force\n" )
run_analysis( suspicious_single_log_file )
print( "\nTest Case 3 -- Multiple Source Brute Force\n" )
run_analysis( suspicious_multiple_log_file )
