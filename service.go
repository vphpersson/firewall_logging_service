package main

import (
	"context"
	"encoding/json/v2"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	motmedelLog "github.com/Motmedel/utils_go/pkg/log"
	motmedelErrorLogger "github.com/Motmedel/utils_go/pkg/log/error_logger"
	"github.com/Motmedel/utils_go/pkg/schema"
	schemaLog "github.com/Motmedel/utils_go/pkg/schema/log"
	"github.com/florianl/go-nflog/v2"
	"github.com/mdlayher/netlink"
	"github.com/vphpersson/firewall_logging/pkg/firewall_logging"
)

const dataset = "firewall_logging"

func main() {
	logger := &motmedelErrorLogger.Logger{
		Logger: slog.New(
			&motmedelLog.ContextHandler{
				Next: slog.NewJSONHandler(
					os.Stdout,
					&slog.HandlerOptions{
						AddSource:   false,
						Level:       slog.LevelInfo,
						ReplaceAttr: schemaLog.ReplaceAttr,
					},
				),
				Extractors: []motmedelLog.ContextExtractor{
					&motmedelLog.ErrorContextExtractor{},
				},
			},
		).With(slog.Group("event", slog.String("dataset", dataset))),
	}
	slog.SetDefault(logger.Logger)

	groupFlag := flag.Int("group", 0, "The NFLOG group to listen on.")
	flag.Parse()

	if *groupFlag <= 0 || *groupFlag > 65535 {
		logger.FatalWithExitingMessage(
			"A valid group must be provided (1-65535).",
			motmedelErrors.NewWithTrace(fmt.Errorf("invalid group: %d", *groupFlag), *groupFlag),
		)
	}

	group := uint16(*groupFlag)
	netfilterLogHandler, err := nflog.Open(&nflog.Config{Group: group, Copymode: nflog.CopyPacket})
	if err != nil {
		logger.FatalWithExitingMessage(
			"An error occurred when opening a connection to the Netfilter log system",
			motmedelErrors.NewWithTrace(fmt.Errorf("nflog open: %w", err), group),
		)
	}
	defer func() {
		if err := netfilterLogHandler.Close(); err != nil {
			logger.Warning(
				"An error occurred when closing the netfilter log handler.",
				motmedelErrors.NewWithTrace(fmt.Errorf("nflog close: %w", err), netfilterLogHandler),
			)
		}
	}()

	// Avoid receiving ENOBUFS errors.
	if err := netfilterLogHandler.SetOption(netlink.NoENOBUFS, true); err != nil {
		logger.FatalWithExitingMessage(
			"An error occurred when setting the NoENOBUFS Netlink option.",
			motmedelErrors.NewWithTrace(fmt.Errorf("netlink set option: %w", err)),
		)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err = netfilterLogHandler.RegisterWithErrorFunc(
		ctx,
		func(attrs nflog.Attribute) int {
			timestamp := time.Now()

			document := &schema.Base{
				Event: &schema.Event{
					Dataset: dataset,
					Reason:  "A packet matched a firewall logging rule.",
				},
			}

			firewall_logging.EnrichWithNflogAttribute(&attrs, document)

			if document.Timestamp == "" {
				document.Timestamp = timestamp.UTC().Format(time.RFC3339Nano)
			}

			document.Message = document.MakeConnectionMessage()
			if ecsRule := document.Rule; ecsRule != nil {
				document.Message += fmt.Sprintf(" - %s-%s", ecsRule.Ruleset, ecsRule.Name)
				if action := document.Event.Action; action != "" {
					document.Message += " " + action
				}
			}

			documentData, err := json.Marshal(document)
			if err != nil {
				logger.Error(
					"An error occurred when marshalling a document. Skipping.",
					motmedelErrors.NewWithTrace(fmt.Errorf("json marshal: %w", err), document),
				)
				return 0
			}

			if _, err := os.Stdout.Write(append(documentData, '\n')); err != nil {
				logger.Error(
					"An error occurred when writing a document to stdout.",
					motmedelErrors.NewWithTrace(fmt.Errorf("os stdout write: %w", err)),
				)
			}

			return 0
		},
		func(err error) int {
			logger.Error("An error occurred when receiving from the Netfilter log handler.", err)
			return 0
		},
	)
	if err != nil {
		logger.FatalWithExitingMessage(
			"An error occurred when registering Netfilter hook functions.",
			motmedelErrors.NewWithTrace(
				fmt.Errorf("nflog register with err func: %w", err),
				netfilterLogHandler,
			),
		)
	}

	<-ctx.Done()
}
