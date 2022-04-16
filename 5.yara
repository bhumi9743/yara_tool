rule malware
{
	meta:
		description="this is malware file"
	strings:
		$a="]4;56;rgb:5f/00/d7"
		$b="[32766S"
	condition:
		$a or $b
}