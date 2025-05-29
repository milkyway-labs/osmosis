package cmd

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/client/tx"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	"github.com/spf13/cobra"
)

const (
	flagEncoding = "encoding"
)

type SignatureData struct {
	Address   string `json:"address"`
	PubKey    string `json:"pub_key"`
	Signature string `json:"signature"`
	Value     string `json:"value"`
}

// GetSignArbitraryCmd returns the command allowing to sign an arbitrary value for later verification
func GetSignArbitraryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sign-arbitrary [value]",
		Short: "Sign the given value using the private key associated to either the address or the private key provided with the --from flag",
		Long: `Sign the given value using the private key associated to either the address or the private key provided with the --from flag.

If the provided address/key name is associated to a key that leverages a Ledger device, the signed value will be placed inside an ADR-036 transaction before being signed.
Otherwise, the provided value will be converted to raw bytes and then signed without any further transformation.

In both cases, after the signature the following data will be printed inside a JSON object:
- the hex-encoded address associated to the key used to sign the value
- the hex-encoded public key associated to the private key used to sign the value
- the hex-encoded signed value 
- the hex-encoded signature value

The printed JSON object can be safely used as the verification proof when connecting a Desmos profile to a centralized application.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			// Build a tx factory
			txFactory, err := tx.NewFactoryCLI(clientCtx, cmd.Flags())
			if err != nil {
				return err
			}

			// Get the value of the "from" flag
			from, _ := cmd.Flags().GetString(flags.FlagFrom)
			_, fromName, _, err := client.GetFromFields(clientCtx, txFactory.Keybase(), from)
			if err != nil {
				return fmt.Errorf("error getting account from keybase: %w", err)
			}

			// Get the key from the keybase
			key, err := txFactory.Keybase().Key(fromName)
			if err != nil {
				return err
			}

			// Sign the value based on the signing mode
			var valueBz, sigBz []byte
			if txFactory.SignMode() == signing.SignMode_SIGN_MODE_LEGACY_AMINO_JSON {
				return fmt.Errorf("signing with SIGN_MODE_LEGACY_AMINO_JSON is not supported for this command")
			} else {
				valueBz, sigBz, err = signRaw(txFactory, key, args[0])
			}

			if err != nil {
				return err
			}

			// Build the signature data output
			pubKey, err := key.GetPubKey()
			if err != nil {
				return err
			}

			// Encode the values
			encoding, err := cmd.Flags().GetString(flagEncoding)
			if err != nil {
				return fmt.Errorf("error getting encoding flag: %w", err)
			}

			var encodedSignature, encodedPubKey, encodedValue string
			switch encoding {
			case "hex":
				encodedSignature = strings.ToLower(hex.EncodeToString(sigBz))
				encodedPubKey = strings.ToLower(hex.EncodeToString(pubKey.Bytes()))
				encodedValue = strings.ToLower(hex.EncodeToString(valueBz))
			case "base64":
				encodedSignature = base64.StdEncoding.EncodeToString(sigBz)
				encodedPubKey = base64.StdEncoding.EncodeToString(pubKey.Bytes())
				encodedValue = base64.StdEncoding.EncodeToString(valueBz)
			default:
				return fmt.Errorf("unsupported encoding: %s. Supported values: hex, base64", encoding)
			}

			signatureData := SignatureData{
				Address:   strings.ToLower(pubKey.Address().String()),
				Signature: encodedSignature,
				PubKey:    encodedPubKey,
				Value:     encodedValue,
			}

			// Serialize the output as JSON and print it
			bz, err := json.Marshal(&signatureData)
			if err != nil {
				return err
			}
			return clientCtx.PrintBytes(bz)
		},
	}

	flags.AddTxFlagsToCmd(cmd)
	cmd.Flags().String(flagEncoding, "hex", "The encoding to use for the signed value. Supported values: hex, base64")

	return cmd
}

// signRaw signs the given value directly by converting it into raw bytes
func signRaw(txFactory tx.Factory, key *keyring.Record, value string) (valueBz []byte, sigBz []byte, err error) {
	valueBz = []byte(value)
	sigBz, _, err = txFactory.Keybase().Sign(key.Name, valueBz, signing.SignMode_SIGN_MODE_TEXTUAL)
	return valueBz, sigBz, err
}
