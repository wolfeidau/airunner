package telemetry

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
)

// InitTelemetry initializes OpenTelemetry with OTLP exporters for metrics and traces.
// Configuration is read from environment variables:
// - OTEL_EXPORTER_OTLP_ENDPOINT: The OTLP endpoint (e.g., https://api.honeycomb.io)
// - OTEL_EXPORTER_OTLP_HEADERS: Headers for authentication (e.g., x-honeycomb-team=API_KEY)
// - OTEL_SERVICE_NAME: Service name override (defaults to serviceName parameter)
//
// Returns a shutdown function that should be called on graceful shutdown.
func InitTelemetry(ctx context.Context, serviceName, version string) (func(context.Context) error, error) {
	// Create resource with service information
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(serviceName),
			semconv.ServiceVersion(version),
		),
		resource.WithFromEnv(),   // Read from OTEL_RESOURCE_ATTRIBUTES env var
		resource.WithProcess(),   // Add process info
		resource.WithHost(),      // Add host info
		resource.WithOSType(),    // Add OS info
		resource.WithContainer(), // Add container info if running in container
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	// Initialize trace provider
	traceShutdown, err := initTraceProvider(ctx, res)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to initialize trace provider, continuing without tracing")
		traceShutdown = func(ctx context.Context) error { return nil }
	}

	// Initialize meter provider
	metricShutdown, err := initMeterProvider(ctx, res)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to initialize meter provider, continuing without metrics")
		metricShutdown = func(ctx context.Context) error { return nil }
	}

	// Set global propagator for distributed tracing
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	log.Info().
		Str("service", serviceName).
		Str("version", version).
		Msg("OpenTelemetry initialized")

	// Return combined shutdown function
	shutdown := func(ctx context.Context) error {
		var errs []error

		if err := traceShutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("trace shutdown: %w", err))
		}

		if err := metricShutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("metric shutdown: %w", err))
		}

		if len(errs) > 0 {
			return fmt.Errorf("telemetry shutdown errors: %v", errs)
		}

		return nil
	}

	return shutdown, nil
}

// initTraceProvider initializes the trace provider with OTLP exporter
func initTraceProvider(ctx context.Context, res *resource.Resource) (func(context.Context) error, error) {
	// Create OTLP trace exporter
	// This reads configuration from environment variables:
	// - OTEL_EXPORTER_OTLP_ENDPOINT
	// - OTEL_EXPORTER_OTLP_HEADERS
	// - OTEL_EXPORTER_OTLP_TRACES_ENDPOINT (if different from metrics)
	traceExporter, err := otlptracegrpc.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create trace exporter: %w", err)
	}

	// Create trace provider with batch span processor
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(traceExporter,
			sdktrace.WithBatchTimeout(5*time.Second),
			sdktrace.WithMaxExportBatchSize(512),
		),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.AlwaysSample()), // TODO: Make this configurable
	)

	// Set as global tracer provider
	otel.SetTracerProvider(tp)

	return tp.Shutdown, nil
}

// initMeterProvider initializes the meter provider with OTLP exporter
func initMeterProvider(ctx context.Context, res *resource.Resource) (func(context.Context) error, error) {
	// Create OTLP metric exporter
	// This reads configuration from environment variables:
	// - OTEL_EXPORTER_OTLP_ENDPOINT
	// - OTEL_EXPORTER_OTLP_HEADERS
	// - OTEL_EXPORTER_OTLP_METRICS_ENDPOINT (if different from traces)
	metricExporter, err := otlpmetricgrpc.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create metric exporter: %w", err)
	}

	// Create meter provider with periodic reader
	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(
			sdkmetric.NewPeriodicReader(
				metricExporter,
				sdkmetric.WithInterval(10*time.Second), // Export metrics every 10 seconds
			),
		),
		sdkmetric.WithResource(res),
	)

	// Set as global meter provider
	otel.SetMeterProvider(mp)

	return mp.Shutdown, nil
}
