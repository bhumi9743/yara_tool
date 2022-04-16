rule malware
{
	meta:
		description="this is malware file"
	strings:
		$a="pE@"
		$b="OPX"
	condition:
		$a or $b
}