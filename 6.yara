rule malware
{
	meta:
		description="this is malware file"
	strings:
		$a="Note! Clink distribution has subfolders."
		$b="You may try "Clink" - bash style autocomplete"
	condition:
		$a or $b
}