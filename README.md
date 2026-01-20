# Blossom Uploader CLI

Blossom Uploader CLI is a command-line tool for uploading, downloading, and listing files on a Blossom server. It uses Nostr for authorization and supports various operations such as uploading files, downloading files by their SHA256 hash, and listing files associated with a public key.

## Installation

To install Blossom Uploader CLI, clone the repository and build the project using Go:

```sh
git clone https://github.com/girino/blossom-cli.git
cd blossom-cli
go mod download
go build -o blossom-cli .
```

## Usage

The CLI supports the following commands: `upload`, `download`, `get`, and `list`.

### Upload a File

To upload a file to the Blossom server:

```sh
./blossom-cli upload -server <server_url> -file <file_path> -privkey <private_key>
```

### Download a File

To download a file from the Blossom server using its SHA256 hash:

```sh
./blossom-cli download -server <server_url> -hash <sha256_hash> -output <output_file>
```

### List Files

To list files associated with a public key:

```sh
./blossom-cli list -server <server_url> -pubkey <pubkey>
```

## Example

Upload a file:

```sh
./blossom-cli upload -server http://example.com -file ./example.txt -privkey nsec1exampleprivatekey
```

Download a file:

```sh
./blossom-cli download -server http://example.com -hash 1234567890abcdef -output ./downloaded.txt
```

List files:

```sh
./blossom-cli list -server http://example.com -pubkey npub1examplepublickey
```

## License

This project is licensed under the Girino's Anarchist License. See the [LICENSE](https://girino.org/license) file for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## Contact

For any questions or feedback, please open an issue or contact me on [nostr](nostr:npub18lav8fkgt8424rxamvk8qq4xuy9n8mltjtgztv2w44hc5tt9vets0hcfsz)