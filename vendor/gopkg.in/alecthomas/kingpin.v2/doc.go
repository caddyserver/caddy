// Package kingpin provides command line interfaces like this:
//
//     $ chat
//     usage: chat [<flags>] <command> [<flags>] [<args> ...]
//
//     Flags:
//       --debug              enable debug mode
//       --help               Show help.
//       --server=127.0.0.1   server address
//
//     Commands:
//       help <command>
//         Show help for a command.
//
//       post [<flags>] <channel>
//         Post a message to a channel.
//
//       register <nick> <name>
//         Register a new user.
//
//     $ chat help post
//     usage: chat [<flags>] post [<flags>] <channel> [<text>]
//
//     Post a message to a channel.
//
//     Flags:
//       --image=IMAGE   image to post
//
//     Args:
//       <channel>   channel to post to
//       [<text>]    text to post
//     $ chat post --image=~/Downloads/owls.jpg pics
//
// From code like this:
//
//     package main
//
//     import "gopkg.in/alecthomas/kingpin.v2"
//
//     var (
//       debug    = kingpin.Flag("debug", "enable debug mode").Default("false").Bool()
//       serverIP = kingpin.Flag("server", "server address").Default("127.0.0.1").IP()
//
//       register     = kingpin.Command("register", "Register a new user.")
//       registerNick = register.Arg("nick", "nickname for user").Required().String()
//       registerName = register.Arg("name", "name of user").Required().String()
//
//       post        = kingpin.Command("post", "Post a message to a channel.")
//       postImage   = post.Flag("image", "image to post").ExistingFile()
//       postChannel = post.Arg("channel", "channel to post to").Required().String()
//       postText    = post.Arg("text", "text to post").String()
//     )
//
//     func main() {
//       switch kingpin.Parse() {
//       // Register user
//       case "register":
//         println(*registerNick)
//
//       // Post message
//       case "post":
//         if *postImage != nil {
//         }
//         if *postText != "" {
//         }
//       }
//     }
package kingpin
