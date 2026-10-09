# Render with: vhs docs/demo.tape
Output docs/demo.gif

Set Shell "bash"
Set FontSize 15
Set Width 1060
Set Height 980
Set Theme "Catppuccin Mocha"
Set Padding 20
Set TypingSpeed 40ms

Hide
Type "export PATH=$PWD/target/release:$PATH; clear"
Enter
Show

Type "whoknocked --file examples/sample-auth.log"
Sleep 600ms
Enter
Sleep 7s
