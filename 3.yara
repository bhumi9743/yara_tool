rule malware
{
	meta:
		description="this is malware file"
	strings:
		$a="You may use next commands in FAR2 macroses."
		$b="callplugin(0x43454D55,1)  Show output of last console program in FAR editor"
	condition:
		$a or $b
}