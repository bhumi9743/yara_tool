rule malware
{
	meta:
		description="this is malware file"
	strings:
		$a="System colors (Standard console 16 colors):"
		$b="[0;30;4;7;42m N "
	condition:
		$a or $b
}