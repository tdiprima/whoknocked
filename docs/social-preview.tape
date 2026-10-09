# Social preview image (GitHub wants 1280x640). Render with: vhs docs/social-preview.tape
Output docs/social-preview.png

Set Shell "bash"
Set FontSize 14
Set Width 1280
Set Height 640
Set Theme "Catppuccin Mocha"
Set Padding 24

Hide
Type "export PATH=$PWD/target/release:$PATH; clear; whoknocked --file examples/sample-auth.log --ip 45.20.13.8 --top 1 --color always | head -n 31; clear; whoknocked --file examples/sample-auth.log --ip 45.20.13.8 --top 1 --color always | head -n 31"
Enter
Sleep 2s
Show
Sleep 500ms
