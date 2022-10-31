package server

import (
	"encoding/xml"
	"fmt"
	"os"

	"github.com/prometheus/client_golang/prometheus"
)

type AuthBrokerStatus struct {
	Text   string `xml:",chardata"`
	Reason string `xml:"reason"`
	Status string `xml:"status"`
}

type Authentication struct {
	Text             string           `xml:",chardata"`
	AuthBrokerStatus AuthBrokerStatus `xml:"authBrokerStatus"`
	SuccessLogins    float64          `xml:"successLogins"`
	FailedLogins     float64          `xml:"failedLogins"`
}

type AirwatchTunnelGatewayStats struct {
	Text          string `xml:",chardata"`
	BackendStatus struct {
		Text   string `xml:",chardata"`
		Reason string `xml:"reason"`
		Status string `xml:"status"`
	} `xml:"backendStatus"`
	EdgeServiceSessionStats struct {
		Text                    string  `xml:",chardata"`
		Identifier              string  `xml:"identifier"`
		TotalSessions           float64 `xml:"totalSessions"`
		HighWaterMarkOfSessions float64 `xml:"highWaterMarkOfSessions"`
		AuthenticatedSessions   float64 `xml:"authenticatedSessions"`
		UnauthenticatedSessions float64 `xml:"unauthenticatedSessions"`
		FailedLoginAttempts     float64 `xml:"failedLoginAttempts"`
		UserCount               float64 `xml:"userCount"`
	} `xml:"edgeServiceSessionStats"`
	EdgeServiceStatus struct {
		Text   string `xml:",chardata"`
		Reason string `xml:"reason"`
		Status string `xml:"status"`
	} `xml:"edgeServiceStatus"`
	Sessions                      float64 `xml:"sessions"`
	SessionsHighWaterMark         float64 `xml:"sessionsHighWaterMark"`
	InternalSessions              float64 `xml:"internalSessions"`
	TotalSessionsSinceStart       float64 `xml:"totalSessionsSinceStart"`
	SessionClosedHandshakes       float64 `xml:"sessionClosedHandshakes"`
	SessionFailedHandshakes       float64 `xml:"sessionFailedHandshakes"`
	Connections                   float64 `xml:"connections"`
	ConnectionsHighWaterMark      float64 `xml:"connectionsHighWaterMark"`
	TotalTCPConnectionsSinceStart float64 `xml:"totalTCPConnectionsSinceStart"`
	TotalUDPConnectionsSinceStart float64 `xml:"totalUDPConnectionsSinceStart"`
	TotalSSLConnectionsSinceStart float64 `xml:"totalSSLConnectionsSinceStart"`
	Timers                        float64 `xml:"timers"`
	TimerHighWaterMark            float64 `xml:"timerHighWaterMark"`
	NatTCPs                       float64 `xml:"natTCPs"`
	NatTCPHighWaterMark           float64 `xml:"natTCPHighWaterMark"`
	TotalNatTCPsSinceStart        float64 `xml:"totalNatTCPsSinceStart"`
	NatTCPSegmentsSent            float64 `xml:"natTCPSegmentsSent"`
	NatTCPSegmentsRetransmitted   float64 `xml:"natTCPSegmentsRetransmitted"`
	NatTCPDownBitPerSec           float64 `xml:"natTCPDownBitPerSec"`
	NatTCPUpBitPerSec             float64 `xml:"natTCPUpBitPerSec"`
	NatUDPs                       float64 `xml:"natUDPs"`
	NatUDPHighWaterMark           float64 `xml:"natUDPHighWaterMark"`
	NatUDPTotalSinceStart         float64 `xml:"natUDPTotalSinceStart"`
	NatUDPDownBitPerSec           float64 `xml:"natUDPDownBitPerSec"`
	NatUDPUpBitPerSec             float64 `xml:"natUDPUpBitPerSec"`
	FlowCollectors                float64 `xml:"flowCollectors"`
	FlowCollectorsHighWaterMark   float64 `xml:"flowCollectorsHighWaterMark"`
	FlowCollectorsTotalSinceStart float64 `xml:"flowCollectorsTotalSinceStart"`
	UseTrafficRules               bool    `xml:"useTrafficRules"`
	TrafficRules                  float64 `xml:"trafficRules"`
	TrafficRuleProxies            float64 `xml:"trafficRuleProxies"`
	TrafficRuleProxiesDown        float64 `xml:"trafficRuleProxiesDown"`
	UpTime                        string  `xml:"upTime"`
	ApiConnectivity               bool    `xml:"apiConnectivity"`
	AwcmConnectivity              bool    `xml:"awcmConnectivity"`
	CascadeMode                   string  `xml:"cascadeMode"`
	CascadeModeBackends           string  `xml:"cascadeModeBackends"`
	CascadeModeBackendsDown       string  `xml:"cascadeModeBackendsDown"`
	CpuCores                      float64 `xml:"cpuCores"`
	CpuUsages                     float64 `xml:"cpuUsages"`
	TotalCpuUsage                 float64 `xml:"totalCpuUsage"`
	ConnectionManagerSnapshot     struct {
		Text              string  `xml:",chardata"`
		ConnectionsPerSec float64 `xml:"connectionsPerSec"`
		DownBitPerSec     float64 `xml:"downBitPerSec"`
		HandshakePerSec   float64 `xml:"handshakePerSec"`
		UpBitPerSec       float64 `xml:"upBitPerSec"`
	} `xml:"connectionManagerSnapshot"`
	SessionManagerSnapshot struct {
		Text              string  `xml:",chardata"`
		ConnectionsPerSec float64 `xml:"connectionsPerSec"`
		DownBitPerSec     float64 `xml:"downBitPerSec"`
		HandshakePerSec   float64 `xml:"handshakePerSec"`
		UpBitPerSec       float64 `xml:"upBitPerSec"`
	} `xml:"sessionManagerSnapshot"`
}

type ApplianceStats struct {
	Text                string  `xml:",chardata"`
	CpuCores            float64 `xml:"cpuCores"`
	TotalCpuLoadPercent float64 `xml:"totalCpuLoadPercent"`
	TotalMemoryMb       float64 `xml:"totalMemoryMb"`
	FreeMemoryMb        float64 `xml:"freeMemoryMb"`
	CpuDetailedStats    struct {
		Text    string  `xml:",chardata"`
		Idle    float64 `xml:"idle"`
		IoWait  float64 `xml:"ioWait"`
		Irq     float64 `xml:"irq"`
		Nice    float64 `xml:"nice"`
		SoftIrq float64 `xml:"softIrq"`
		Steal   float64 `xml:"steal"`
		System  float64 `xml:"system"`
		User    float64 `xml:"user"`
	} `xml:"cpuDetailedStats"`
}

type EdgeServiceSessionStats struct {
	Text                    string  `xml:",chardata"`
	Identifier              string  `xml:"identifier"`
	TotalSessions           float64 `xml:"totalSessions"`
	HighWaterMarkOfSessions float64 `xml:"highWaterMarkOfSessions"`
	AuthenticatedSessions   float64 `xml:"authenticatedSessions"`
	UnauthenticatedSessions float64 `xml:"unauthenticatedSessions"`
	FailedLoginAttempts     float64 `xml:"failedLoginAttempts"`
	UserCount               float64 `xml:"userCount"`
}

type AccessPointStatusAndStats struct {
	XMLName                       xml.Name `xml:"accessPointStatusAndStats"`
	Text                          string   `xml:",chardata"`
	SessionCount                  float64  `xml:"sessionCount"`
	AuthenticatedSessionCount     float64  `xml:"authenticatedSessionCount"`
	AuthenticatedViewSessionCount float64  `xml:"authenticatedViewSessionCount"`
	OpenIncomingConnectionCount   float64  `xml:"openIncomingConnectionCount"`
	HighWaterMark                 float64  `xml:"highWaterMark"`
	// TODO: fix time
	TimeStamp     float64 `xml:"timeStamp"`
	Date          string  `xml:"date"`
	OverAllStatus struct {
		Text   string `xml:",chardata"`
		Status string `xml:"status"`
	} `xml:"overAllStatus"`

	Authentication             Authentication             `xml:"authentication"`
	EdgeServiceSessionStats    EdgeServiceSessionStats    `xml:"edgeServiceSessionStats"`
	ApplianceStats             ApplianceStats             `xml:"applianceStats"`
	AirwatchTunnelGatewayStats AirwatchTunnelGatewayStats `xml:"airwatchTunnelGatewayStats"`
}

var (
	sessionCount = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "SessionCount",
			Help: "SessionCount help",
		},
	)
	authenticatedSessionCount = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "AuthenticatedSessionCount",
			Help: "AuthenticatedSessionCount help",
		},
	)
	authenticatedViewSessionCount = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "AuthenticatedViewSessionCount",
			Help: "AuthenticatedViewSessionCount help",
		},
	)
	openIncomingConnectionCount = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "OpenIncomingConnectionCount",
			Help: "OpenIncomingConnectionCount help",
		},
	)
	highWaterMark = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "HighWaterMark",
			Help: "HighWaterMark help",
		},
	)
	timeStamp = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "TimeStamp",
			Help: "TimeStamp help",
		},
	)
	date = prometheus.NewDesc(
		"Date",
		"Date help",
		nil, nil,
	)
	overAllStatus = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "OverAllStatus",
			Help: "OverAllStatus help",
		},
	)
	authenticationAuthBrokerStatusReason = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "AuthBrokerStatusReason",
			Help: "AuthBrokerStatusReason help",
		},
	)

	authenticationAuthBrokerStatus = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "AuthBrokerStatus",
			Help: "AuthBrokerStatus help",
		},
	)

	authenticationSuccessLogins = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "authenticationSuccessLogins",
			Help: "authenticationSuccessLogins help",
		},
	)
	authenticationFailedLogins = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "authenticationFailedLogins",
			Help: "authenticationFailedLogins help",
		},
	)
	airwatchTunnelGatewayStatsBackendStatus = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsBackendStatus",
			Help: "airwatchTunnelGatewayStatsBackendStatus help",
		},
	)

	airwatchTunnelGatewayStatsBackendStatusReason = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsBackendStatusReason",
			Help: "airwatchTunnelGatewayStatsBackendStatusReason help",
		},
	)
	airwatchTunnelGatewayStatsEdgeServiceSessionStatsIdentifier = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsEdgeServiceSessionStatsIdentifier",
			Help: "airwatchTunnelGatewayStatsEdgeServiceSessionStatsIdentifier help",
		},
	)
	airwatchTunnelGatewayStatsEdgeServiceSessionStatsTotalSessions = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsEdgeServiceSessionStatsTotalSessions",
			Help: "airwatchTunnelGatewayStatsEdgeServiceSessionStatsTotalSessions help",
		},
	)
	airwatchTunnelGatewayStatsEdgeServiceSessionStatsHighWaterMarkOfSessions = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsEdgeServiceSessionStatsHighWaterMarkOfSessions",
			Help: "airwatchTunnelGatewayStatsEdgeServiceSessionStatsHighWaterMarkOfSessions help",
		},
	)
	airwatchTunnelGatewayStatsEdgeServiceSessionStatsAuthenticatedSessions = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsEdgeServiceSessionStatsAuthenticatedSessions",
			Help: "airwatchTunnelGatewayStatsEdgeServiceSessionStatsAuthenticatedSessions help",
		},
	)
	airwatchTunnelGatewayStatsEdgeServiceSessionStatsUnauthenticatedSessions = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsEdgeServiceSessionStatsUnauthenticatedSessions",
			Help: "airwatchTunnelGatewayStatsEdgeServiceSessionStatsUnauthenticatedSessions help",
		},
	)
	airwatchTunnelGatewayStatsEdgeServiceSessionStatsFailedLoginAttempts = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsEdgeServiceSessionStatsFailedLoginAttempts",
			Help: "airwatchTunnelGatewayStatsEdgeServiceSessionStatsFailedLoginAttempts help",
		},
	)
	airwatchTunnelGatewayStatsEdgeServiceSessionStatsUserCount = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsEdgeServiceSessionStatsUserCount",
			Help: "airwatchTunnelGatewayStatsEdgeServiceSessionStatsUserCount help",
		},
	)
	airwatchTunnelGatewayStatsEdgeServiceStatus = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsEdgeServiceStatus",
			Help: "airwatchTunnelGatewayStatsEdgeServiceStatus help",
		},
	)
	airwatchTunnelGatewayStatsEdgeServiceStatusReason = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsEdgeServiceStatusReason",
			Help: "airwatchTunnelGatewayStatsEdgeServiceStatusReason help",
		},
	)
	airwatchTunnelGatewayStatsSessions = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsSessions",
			Help: "airwatchTunnelGatewayStatsSessions help",
		},
	)
	airwatchTunnelGatewayStatsSessionsHighWaterMark = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsSessionsHighWaterMark",
			Help: "airwatchTunnelGatewayStatsSessionsHighWaterMark help",
		},
	)
	airwatchTunnelGatewayStatsInternalSessions = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsInternalSessions",
			Help: "airwatchTunnelGatewayStatsInternalSessions help",
		},
	)
	airwatchTunnelGatewayStatsTotalSessionsSinceStart = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsTotalSessionsSinceStart",
			Help: "airwatchTunnelGatewayStatsTotalSessionsSinceStart help",
		},
	)
	airwatchTunnelGatewayStatsSessionClosedHandshakes = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsSessionClosedHandshakes",
			Help: "airwatchTunnelGatewayStatsSessionClosedHandshakes help",
		},
	)
	airwatchTunnelGatewayStatsSessionFailedHandshakes = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsSessionFailedHandshakes",
			Help: "airwatchTunnelGatewayStatsSessionFailedHandshakes help",
		},
	)
	airwatchTunnelGatewayStatsConnections = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsConnections",
			Help: "airwatchTunnelGatewayStatsConnections help",
		},
	)
	airwatchTunnelGatewayStatsConnectionsHighWaterMark = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsConnectionsHighWaterMark",
			Help: "airwatchTunnelGatewayStatsConnectionsHighWaterMark help",
		},
	)
	airwatchTunnelGatewayStatsTotalTCPConnectionsSinceStart = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsTotalTCPConnectionsSinceStart",
			Help: "airwatchTunnelGatewayStatsTotalTCPConnectionsSinceStart help",
		},
	)
	airwatchTunnelGatewayStatsTotalUDPConnectionsSinceStart = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsTotalUDPConnectionsSinceStart",
			Help: "airwatchTunnelGatewayStatsTotalUDPConnectionsSinceStart help",
		},
	)
	airwatchTunnelGatewayStatsTotalSSLConnectionsSinceStart = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsTotalSSLConnectionsSinceStart",
			Help: "airwatchTunnelGatewayStatsTotalSSLConnectionsSinceStart help",
		},
	)
	airwatchTunnelGatewayStatsTimers = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsTimers",
			Help: "airwatchTunnelGatewayStatsTimers help",
		},
	)
	airwatchTunnelGatewayStatsTimerHighWaterMark = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsTimerHighWaterMark",
			Help: "airwatchTunnelGatewayStatsTimerHighWaterMark help",
		},
	)
	airwatchTunnelGatewayStatsNatTCPs = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsNatTCPs",
			Help: "airwatchTunnelGatewayStatsNatTCPs help",
		},
	)
	airwatchTunnelGatewayStatsNatTCPHighWaterMark = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsNatTCPHighWaterMark",
			Help: "airwatchTunnelGatewayStatsNatTCPHighWaterMark help",
		},
	)
	airwatchTunnelGatewayStatsTotalNatTCPsSinceStart = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsTotalNatTCPsSinceStart",
			Help: "airwatchTunnelGatewayStatsTotalNatTCPsSinceStart help",
		},
	)
	airwatchTunnelGatewayStatsNatTCPSegmentsSent = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsNatTCPSegmentsSent",
			Help: "airwatchTunnelGatewayStatsNatTCPSegmentsSent help",
		},
	)
	airwatchTunnelGatewayStatsTotalNatTCPSegmentsRetransmitted = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsTotalNatTCPSegmentsRetransmitted",
			Help: "airwatchTunnelGatewayStatsTotalNatTCPSegmentsRetransmitted help",
		},
	)
	airwatchTunnelGatewayStatsNatTCPDownBitPerSec = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsNatTCPDownBitPerSec",
			Help: "airwatchTunnelGatewayStatsNatTCPDownBitPerSec help",
		},
	)
	airwatchTunnelGatewayStatsNatTCPUpBitPerSec = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsNatTCPUpBitPerSec",
			Help: "airwatchTunnelGatewayStatsNatTCPUpBitPerSec help",
		},
	)
	airwatchTunnelGatewayStatsNatUDPs = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsNatUDPs",
			Help: "airwatchTunnelGatewayStatsNatUDPs help",
		},
	)
	airwatchTunnelGatewayStatsNatUDPHighWaterMark = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsNatUDPHighWaterMark",
			Help: "airwatchTunnelGatewayStatsNatUDPHighWaterMark help",
		},
	)
	airwatchTunnelGatewayStatsNatUDPTotalSinceStart = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsNatUDPTotalSinceStart",
			Help: "airwatchTunnelGatewayStatsNatUDPTotalSinceStart help",
		},
	)
	airwatchTunnelGatewayStatsNatUDPDownBitPerSec = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsNatUDPDownBitPerSec",
			Help: "airwatchTunnelGatewayStatsNatUDPDownBitPerSec help",
		},
	)

	airwatchTunnelGatewayStatsNatUDPUpBitPerSec = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsNatUDPUpBitPerSec",
			Help: "airwatchTunnelGatewayStatsNatUDPUpBitPerSec help",
		},
	)
	airwatchTunnelGatewayStatsFlowCollectorsHighWaterMark = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsFlowCollectorsHighWaterMark",
			Help: "airwatchTunnelGatewayStatsFlowCollectorsHighWaterMark help",
		},
	)
	airwatchTunnelGatewayStatsFlowCollectorsTotalSinceStart = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsFlowCollectorsTotalSinceStart",
			Help: "airwatchTunnelGatewayStatsFlowCollectorsTotalSinceStart help",
		},
	)
	airwatchTunnelGatewayStatsUseTrafficRules = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsUseTrafficRules",
			Help: "airwatchTunnelGatewayStatsUseTrafficRules help",
		},
	)
	airwatchTunnelGatewayStatsTrafficRuleProxies = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsTrafficRuleProxies",
			Help: "airwatchTunnelGatewayStatsTrafficRuleProxies help",
		},
	)
	airwatchTunnelGatewayStatsApiConnectivity = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsApiConnectivity",
			Help: "airwatchTunnelGatewayStatsApiConnectivity help",
		},
	)
	airwatchTunnelGatewayStatsAwcmConnectivity = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsAwcmConnectivity",
			Help: "airwatchTunnelGatewayStatsAwcmConnectivity help",
		},
	)
	airwatchTunnelGatewayStatsCascadeMode = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsCascadeMode",
			Help: "airwatchTunnelGatewayStatsCascadeMode help",
		},
	)
	airwatchTunnelGatewayStatsCascadeModeBackends = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsCascadeModeBackends",
			Help: "airwatchTunnelGatewayStatsCascadeModeBackends help",
		},
	)
	airwatchTunnelGatewayStatsCascadeModeBackendsDown = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsCascadeModeBackendsDown",
			Help: "airwatchTunnelGatewayStatsCascadeModeBackendsDown help",
		},
	)
	airwatchTunnelGatewayStatsCpuCores = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsCpuCores",
			Help: "airwatchTunnelGatewayStatsCpuCores help",
		},
	)
	airwatchTunnelGatewayStatsCpuUsages = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsCpuUsages",
			Help: "airwatchTunnelGatewayStatsCpuUsages help",
		},
	)
	airwatchTunnelGatewayStatsConnectionManagerSnapshotConnectionsPerSec = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsConnectionManagerSnapshotConnectionsPerSec",
			Help: "airwatchTunnelGatewayStatsConnectionManagerSnapshotConnectionsPerSec help",
		},
	)
	airwatchTunnelGatewayStatsConnectionManagerSnapshotHandshakePerSec = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsConnectionManagerSnapshotHandshakePerSec",
			Help: "airwatchTunnelGatewayStatsConnectionManagerSnapshotHandshakePerSec help",
		},
	)
	airwatchTunnelGatewayStatsConnectionManagerSnapshotUpBitPerSec = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsConnectionManagerSnapshotUpBitPerSec",
			Help: "airwatchTunnelGatewayStatsConnectionManagerSnapshotUpBitPerSec help",
		},
	)
	airwatchTunnelGatewayStatsTotalCpuUsage = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsTotalCpuUsage",
			Help: "airwatchTunnelGatewayStatsTotalCpuUsage help",
		},
	)
	airwatchTunnelGatewayStatsSessionManagerSnapshotConnectionsPerSec = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsSessionManagerSnapshotConnectionsPerSec",
			Help: "airwatchTunnelGatewayStatsSessionManagerSnapshotConnectionsPerSec help",
		},
	)
	airwatchTunnelGatewayStatsSessionManagerSnapshotDownBitPerSec = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsSessionManagerSnapshotDownBitPerSec",
			Help: "airwatchTunnelGatewayStatsSessionManagerSnapshotDownBitPerSec help",
		},
	)
	airwatchTunnelGatewayStatsSessionManagerSnapshotHandshakePerSec = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsSessionManagerSnapshotHandshakePerSec",
			Help: "airwatchTunnelGatewayStatsSessionManagerSnapshotHandshakePerSec help",
		},
	)
	airwatchTunnelGatewayStatsSessionManagerSnapshotUpBitPerSec = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "airwatchTunnelGatewayStatsSessionManagerSnapshotUpBitPerSec",
			Help: "airwatchTunnelGatewayStatsSessionManagerSnapshotUpBitPerSec help",
		},
	)
	edgeServiceSessionStats = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "edgeServiceSessionStats",
			Help: "edgeServiceSessionStats help",
		},
	)
	applianceStatsCpuCores = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "applianceStatsCpuCores",
			Help: "applianceStatsCpuCores help",
		},
	)
	applianceStatsTotalCpuLoadPercent = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "applianceStatsTotalCpuLoadPercent",
			Help: "applianceStatsTotalCpuLoadPercent help",
		},
	)
	applianceStatsTotalMemoryMb = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "applianceStatsTotalMemoryMb",
			Help: "applianceStatsTotalMemoryMb help",
		},
	)
	applianceStatsFreeMemoryMb = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "applianceStatsFreeMemoryMb",
			Help: "applianceStatsFreeMemoryMb help",
		},
	)
	applianceStatsCpuDetailedStatsIdle = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "applianceStatsCpuDetailedStatsIdle",
			Help: "applianceStatsCpuDetailedStatsIdle help",
		},
	)
	applianceStatsCpuDetailedStatsIoWait = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "applianceStatsCpuDetailedStatsIoWait",
			Help: "applianceStatsCpuDetailedStatsIoWait help",
		},
	)
	applianceStatsCpuDetailedStatsIrq = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "applianceStatsCpuDetailedStatsIrq",
			Help: "applianceStatsCpuDetailedStatsIrq help",
		},
	)
	applianceStatsCpuDetailedStatsNice = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "applianceStatsCpuDetailedStatsNice",
			Help: "applianceStatsCpuDetailedStatsNice help",
		},
	)
	applianceStatsCpuDetailedStatsSoftIrq = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "applianceStatsCpuDetailedStatsSoftIrq",
			Help: "applianceStatsCpuDetailedStatsSoftIrq help",
		},
	)
	applianceStatsCpuDetailedStatsSteal = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "applianceStatsCpuDetailedStatsSteal",
			Help: "applianceStatsCpuDetailedStatsSteal help",
		},
	)
	applianceStatsCpuDetailedStatsSystem = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "applianceStatsCpuDetailedStatsSystem",
			Help: "applianceStatsCpuDetailedStatsSystem help",
		},
	)
	applianceStatsCpuDetailedStatsUser = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "applianceStatsCpuDetailedStatsUser",
			Help: "applianceStatsCpuDetailedStatsUser help",
		},
	)
)

func init() {
	prometheus.MustRegister(sessionCount)
	prometheus.MustRegister(authenticatedSessionCount)
	prometheus.MustRegister(authenticatedViewSessionCount)
	prometheus.MustRegister(openIncomingConnectionCount)
	prometheus.MustRegister(highWaterMark)
	prometheus.MustRegister(timeStamp)
	//	prometheus.MustRegister(date)
	prometheus.MustRegister(overAllStatus)
	prometheus.MustRegister(authenticationAuthBrokerStatusReason)
	prometheus.MustRegister(authenticationAuthBrokerStatus)
	prometheus.MustRegister(authenticationSuccessLogins)
	prometheus.MustRegister(authenticationFailedLogins)
	prometheus.MustRegister(airwatchTunnelGatewayStatsBackendStatus)
	prometheus.MustRegister(airwatchTunnelGatewayStatsBackendStatusReason)
	prometheus.MustRegister(airwatchTunnelGatewayStatsEdgeServiceSessionStatsIdentifier)
	prometheus.MustRegister(airwatchTunnelGatewayStatsEdgeServiceSessionStatsTotalSessions)
	prometheus.MustRegister(airwatchTunnelGatewayStatsEdgeServiceSessionStatsHighWaterMarkOfSessions)
	prometheus.MustRegister(airwatchTunnelGatewayStatsEdgeServiceSessionStatsAuthenticatedSessions)
	prometheus.MustRegister(airwatchTunnelGatewayStatsEdgeServiceSessionStatsUnauthenticatedSessions)
	prometheus.MustRegister(airwatchTunnelGatewayStatsEdgeServiceSessionStatsFailedLoginAttempts)
	prometheus.MustRegister(airwatchTunnelGatewayStatsEdgeServiceSessionStatsUserCount)
	prometheus.MustRegister(airwatchTunnelGatewayStatsEdgeServiceStatus)
	prometheus.MustRegister(airwatchTunnelGatewayStatsEdgeServiceStatusReason)
	prometheus.MustRegister(airwatchTunnelGatewayStatsSessions)
	prometheus.MustRegister(airwatchTunnelGatewayStatsSessionsHighWaterMark)
	prometheus.MustRegister(airwatchTunnelGatewayStatsInternalSessions)
	prometheus.MustRegister(airwatchTunnelGatewayStatsTotalSessionsSinceStart)
	prometheus.MustRegister(airwatchTunnelGatewayStatsSessionClosedHandshakes)
	prometheus.MustRegister(airwatchTunnelGatewayStatsSessionFailedHandshakes)
	prometheus.MustRegister(airwatchTunnelGatewayStatsConnections)
	prometheus.MustRegister(airwatchTunnelGatewayStatsConnectionsHighWaterMark)
	prometheus.MustRegister(airwatchTunnelGatewayStatsTotalTCPConnectionsSinceStart)
	prometheus.MustRegister(airwatchTunnelGatewayStatsTotalUDPConnectionsSinceStart)
	prometheus.MustRegister(airwatchTunnelGatewayStatsTotalSSLConnectionsSinceStart)
	prometheus.MustRegister(airwatchTunnelGatewayStatsTimers)
	prometheus.MustRegister(airwatchTunnelGatewayStatsTimerHighWaterMark)
	prometheus.MustRegister(airwatchTunnelGatewayStatsNatTCPs)
	prometheus.MustRegister(airwatchTunnelGatewayStatsNatTCPHighWaterMark)
	prometheus.MustRegister(airwatchTunnelGatewayStatsTotalNatTCPsSinceStart)
	prometheus.MustRegister(airwatchTunnelGatewayStatsNatTCPSegmentsSent)
	prometheus.MustRegister(airwatchTunnelGatewayStatsTotalNatTCPSegmentsRetransmitted)
	prometheus.MustRegister(airwatchTunnelGatewayStatsNatTCPDownBitPerSec)
	prometheus.MustRegister(airwatchTunnelGatewayStatsNatTCPUpBitPerSec)
	prometheus.MustRegister(airwatchTunnelGatewayStatsNatUDPs)
	prometheus.MustRegister(airwatchTunnelGatewayStatsNatUDPHighWaterMark)
	prometheus.MustRegister(airwatchTunnelGatewayStatsNatUDPTotalSinceStart)
	prometheus.MustRegister(airwatchTunnelGatewayStatsNatUDPDownBitPerSec)
	prometheus.MustRegister(airwatchTunnelGatewayStatsNatUDPUpBitPerSec)
	prometheus.MustRegister(airwatchTunnelGatewayStatsFlowCollectorsHighWaterMark)
	prometheus.MustRegister(airwatchTunnelGatewayStatsFlowCollectorsTotalSinceStart)
	prometheus.MustRegister(airwatchTunnelGatewayStatsUseTrafficRules)
	prometheus.MustRegister(airwatchTunnelGatewayStatsTrafficRuleProxies)
	prometheus.MustRegister(airwatchTunnelGatewayStatsApiConnectivity)
	prometheus.MustRegister(airwatchTunnelGatewayStatsAwcmConnectivity)
	prometheus.MustRegister(airwatchTunnelGatewayStatsCascadeMode)
	prometheus.MustRegister(airwatchTunnelGatewayStatsCascadeModeBackends)
	prometheus.MustRegister(airwatchTunnelGatewayStatsCascadeModeBackendsDown)
	prometheus.MustRegister(airwatchTunnelGatewayStatsCpuCores)
	prometheus.MustRegister(airwatchTunnelGatewayStatsCpuUsages)
	prometheus.MustRegister(airwatchTunnelGatewayStatsConnectionManagerSnapshotConnectionsPerSec)
	prometheus.MustRegister(airwatchTunnelGatewayStatsConnectionManagerSnapshotHandshakePerSec)
	prometheus.MustRegister(airwatchTunnelGatewayStatsConnectionManagerSnapshotUpBitPerSec)
	prometheus.MustRegister(airwatchTunnelGatewayStatsTotalCpuUsage)
	prometheus.MustRegister(airwatchTunnelGatewayStatsSessionManagerSnapshotConnectionsPerSec)
	prometheus.MustRegister(airwatchTunnelGatewayStatsSessionManagerSnapshotDownBitPerSec)
	prometheus.MustRegister(airwatchTunnelGatewayStatsSessionManagerSnapshotHandshakePerSec)
	prometheus.MustRegister(airwatchTunnelGatewayStatsSessionManagerSnapshotUpBitPerSec)
	prometheus.MustRegister(edgeServiceSessionStats)
	prometheus.MustRegister(applianceStatsCpuCores)
	prometheus.MustRegister(applianceStatsTotalCpuLoadPercent)
	prometheus.MustRegister(applianceStatsTotalMemoryMb)
	prometheus.MustRegister(applianceStatsFreeMemoryMb)
	prometheus.MustRegister(applianceStatsCpuDetailedStatsIdle)
	prometheus.MustRegister(applianceStatsCpuDetailedStatsIoWait)
	prometheus.MustRegister(applianceStatsCpuDetailedStatsIrq)
	prometheus.MustRegister(applianceStatsCpuDetailedStatsNice)
	prometheus.MustRegister(applianceStatsCpuDetailedStatsSoftIrq)
	prometheus.MustRegister(applianceStatsCpuDetailedStatsSteal)
	prometheus.MustRegister(applianceStatsCpuDetailedStatsSystem)
	prometheus.MustRegister(applianceStatsCpuDetailedStatsUser)
}

func getStats(args *Args) {
	data, err := os.ReadFile("./teststats.xml")
	if err != nil {
		fmt.Println("Can not read file")
		os.Exit(1)
	}

	//	fmt.Println(string(data))

	var a AccessPointStatusAndStats

	err = xml.Unmarshal(data, &a)
	if err != nil {
		fmt.Println(err)
		fmt.Println("Unmarshal error")
		os.Exit(1)
	}

	sessionCount.Set(a.SessionCount)
	authenticatedSessionCount.Set(a.AuthenticatedSessionCount)
	authenticatedViewSessionCount.Set(a.AuthenticatedViewSessionCount)
	openIncomingConnectionCount.Set(a.OpenIncomingConnectionCount)
	highWaterMark.Set(a.HighWaterMark)
	timeStamp.Set(a.TimeStamp)
	//	date.Set(a.Date)
	//	overAllStatus.Set(a.OverAllStatus)
	//	authenticationAuthBrokerStatusReason.Set(a.Authentication.AuthBrokerStatus.Reason)
	//	authenticationAuthBrokerStatus.Set(a.authenticationAuthBrokerStatus)
	authenticationSuccessLogins.Set(a.Authentication.SuccessLogins)
	authenticationFailedLogins.Set(a.Authentication.FailedLogins)
	//	airwatchTunnelGatewayStatsBackendStatus.Set(a.AirwatchTunnelGatewayStats.BackendStatus)
	//	airwatchTunnelGatewayStatsBackendStatusReason.Set(a.AirwatchTunnelGatewayStats.BackendStatusreason)
	//  airwatchTunnelGatewayStatsEdgeServiceSessionStatsIdentifier.Set(a.AirwatchTunnelGatewayStats.EdgeServiceSessionStats.Identifier)
	airwatchTunnelGatewayStatsEdgeServiceSessionStatsTotalSessions.Set(a.AirwatchTunnelGatewayStats.TotalSessionsSinceStart)
	airwatchTunnelGatewayStatsEdgeServiceSessionStatsHighWaterMarkOfSessions.Set(a.AirwatchTunnelGatewayStats.EdgeServiceSessionStats.HighWaterMarkOfSessions)
	airwatchTunnelGatewayStatsEdgeServiceSessionStatsAuthenticatedSessions.Set(a.AirwatchTunnelGatewayStats.EdgeServiceSessionStats.AuthenticatedSessions)
	airwatchTunnelGatewayStatsEdgeServiceSessionStatsUnauthenticatedSessions.Set(a.AirwatchTunnelGatewayStats.EdgeServiceSessionStats.UnauthenticatedSessions)
	airwatchTunnelGatewayStatsEdgeServiceSessionStatsFailedLoginAttempts.Set(a.AirwatchTunnelGatewayStats.EdgeServiceSessionStats.FailedLoginAttempts)
	airwatchTunnelGatewayStatsEdgeServiceSessionStatsUserCount.Set(a.AirwatchTunnelGatewayStats.EdgeServiceSessionStats.UserCount)
	//	airwatchTunnelGatewayStatsEdgeServiceStatus.Set()
	//	airwatchTunnelGatewayStatsEdgeServiceStatusReason
	airwatchTunnelGatewayStatsSessions.Set(a.AirwatchTunnelGatewayStats.Sessions)
	airwatchTunnelGatewayStatsSessionsHighWaterMark.Set(a.AirwatchTunnelGatewayStats.SessionsHighWaterMark)
	airwatchTunnelGatewayStatsInternalSessions.Set(a.AirwatchTunnelGatewayStats.InternalSessions)
	airwatchTunnelGatewayStatsTotalSessionsSinceStart.Set(a.AirwatchTunnelGatewayStats.TotalSessionsSinceStart)
	airwatchTunnelGatewayStatsSessionClosedHandshakes.Set(a.AirwatchTunnelGatewayStats.SessionClosedHandshakes)
	airwatchTunnelGatewayStatsSessionFailedHandshakes.Set(a.AirwatchTunnelGatewayStats.SessionFailedHandshakes)
	airwatchTunnelGatewayStatsConnections.Set(a.AirwatchTunnelGatewayStats.Connections)
	airwatchTunnelGatewayStatsConnectionsHighWaterMark.Set(a.AirwatchTunnelGatewayStats.ConnectionsHighWaterMark)
	airwatchTunnelGatewayStatsTotalTCPConnectionsSinceStart.Set(a.AirwatchTunnelGatewayStats.TotalTCPConnectionsSinceStart)
	airwatchTunnelGatewayStatsTotalUDPConnectionsSinceStart.Set(a.AirwatchTunnelGatewayStats.TotalUDPConnectionsSinceStart)
	airwatchTunnelGatewayStatsTotalSSLConnectionsSinceStart.Set(a.AirwatchTunnelGatewayStats.TotalSSLConnectionsSinceStart)
	airwatchTunnelGatewayStatsTimers.Set(a.AirwatchTunnelGatewayStats.Timers)
	airwatchTunnelGatewayStatsTimerHighWaterMark.Set(a.AirwatchTunnelGatewayStats.TimerHighWaterMark)
	airwatchTunnelGatewayStatsNatTCPs.Set(a.AirwatchTunnelGatewayStats.NatTCPs)
	airwatchTunnelGatewayStatsNatTCPHighWaterMark.Set(a.AirwatchTunnelGatewayStats.NatTCPHighWaterMark)
	airwatchTunnelGatewayStatsTotalNatTCPsSinceStart.Set(a.AirwatchTunnelGatewayStats.TotalNatTCPsSinceStart)
	airwatchTunnelGatewayStatsNatTCPSegmentsSent.Set(a.AirwatchTunnelGatewayStats.NatTCPSegmentsSent)
	airwatchTunnelGatewayStatsTotalNatTCPSegmentsRetransmitted.Set(a.AirwatchTunnelGatewayStats.NatTCPSegmentsRetransmitted)
	airwatchTunnelGatewayStatsNatTCPDownBitPerSec.Set(a.AirwatchTunnelGatewayStats.NatTCPDownBitPerSec)
	airwatchTunnelGatewayStatsNatTCPUpBitPerSec.Set(a.AirwatchTunnelGatewayStats.NatTCPUpBitPerSec)
	airwatchTunnelGatewayStatsNatUDPs.Set(a.AirwatchTunnelGatewayStats.NatUDPs)
	airwatchTunnelGatewayStatsNatUDPHighWaterMark.Set(a.AirwatchTunnelGatewayStats.NatUDPHighWaterMark)
	airwatchTunnelGatewayStatsNatUDPTotalSinceStart.Set(a.AirwatchTunnelGatewayStats.NatUDPTotalSinceStart)
	airwatchTunnelGatewayStatsNatUDPDownBitPerSec.Set(a.AirwatchTunnelGatewayStats.NatUDPDownBitPerSec)
	airwatchTunnelGatewayStatsNatUDPUpBitPerSec.Set(a.AirwatchTunnelGatewayStats.NatUDPUpBitPerSec)
	airwatchTunnelGatewayStatsFlowCollectorsHighWaterMark.Set(a.AirwatchTunnelGatewayStats.FlowCollectorsHighWaterMark)
	airwatchTunnelGatewayStatsFlowCollectorsTotalSinceStart.Set(a.AirwatchTunnelGatewayStats.FlowCollectorsTotalSinceStart)
	//	airwatchTunnelGatewayStatsUseTrafficRules.Set(a.AirwatchTunnelGatewayStats.UseTrafficRules)
	airwatchTunnelGatewayStatsTrafficRuleProxies.Set(a.AirwatchTunnelGatewayStats.TrafficRuleProxies)
	//	airwatchTunnelGatewayStatsApiConnectivity.Set(a.AirwatchTunnelGatewayStats.ApiConnectivity)
	//	airwatchTunnelGatewayStatsAwcmConnectivity.Set(a.AirwatchTunnelGatewayStats.AwcmConnectivity)
	//	airwatchTunnelGatewayStatsCascadeMode.Set(a.AirwatchTunnelGatewayStats.CascadeMode)
	//	airwatchTunnelGatewayStatsCascadeModeBackends.Set(a.AirwatchTunnelGatewayStats.CascadeModeBackends)
	//	airwatchTunnelGatewayStatsCascadeModeBackendsDown.Set(a.AirwatchTunnelGatewayStats.CascadeModeBackendsDown)
	airwatchTunnelGatewayStatsCpuCores.Set(a.AirwatchTunnelGatewayStats.CpuCores)
	airwatchTunnelGatewayStatsCpuUsages.Set(a.AirwatchTunnelGatewayStats.CpuUsages)
	airwatchTunnelGatewayStatsConnectionManagerSnapshotConnectionsPerSec.Set(a.AirwatchTunnelGatewayStats.ConnectionManagerSnapshot.ConnectionsPerSec)
	airwatchTunnelGatewayStatsConnectionManagerSnapshotHandshakePerSec.Set(a.AirwatchTunnelGatewayStats.ConnectionManagerSnapshot.HandshakePerSec)
	airwatchTunnelGatewayStatsConnectionManagerSnapshotUpBitPerSec.Set(a.AirwatchTunnelGatewayStats.ConnectionManagerSnapshot.HandshakePerSec)
	airwatchTunnelGatewayStatsTotalCpuUsage.Set(a.AirwatchTunnelGatewayStats.TotalCpuUsage)
	airwatchTunnelGatewayStatsSessionManagerSnapshotConnectionsPerSec.Set(a.AirwatchTunnelGatewayStats.SessionManagerSnapshot.ConnectionsPerSec)
	airwatchTunnelGatewayStatsSessionManagerSnapshotDownBitPerSec.Set(a.AirwatchTunnelGatewayStats.SessionManagerSnapshot.DownBitPerSec)
	airwatchTunnelGatewayStatsSessionManagerSnapshotHandshakePerSec.Set(a.AirwatchTunnelGatewayStats.SessionManagerSnapshot.HandshakePerSec)
	airwatchTunnelGatewayStatsSessionManagerSnapshotUpBitPerSec.Set(a.AirwatchTunnelGatewayStats.SessionManagerSnapshot.UpBitPerSec)
	//	edgeServiceSessionStats.Set(a.EdgeServiceSessionStats)
	applianceStatsCpuCores.Set(a.ApplianceStats.CpuCores)
	applianceStatsTotalCpuLoadPercent.Set(a.ApplianceStats.TotalCpuLoadPercent)
	applianceStatsTotalMemoryMb.Set(a.ApplianceStats.TotalMemoryMb)
	applianceStatsFreeMemoryMb.Set(a.ApplianceStats.FreeMemoryMb)
	applianceStatsCpuDetailedStatsIdle.Set(a.ApplianceStats.CpuDetailedStats.Idle)
	applianceStatsCpuDetailedStatsIoWait.Set(a.ApplianceStats.CpuDetailedStats.IoWait)
	applianceStatsCpuDetailedStatsIrq.Set(a.ApplianceStats.CpuDetailedStats.Irq)
	applianceStatsCpuDetailedStatsNice.Set(a.ApplianceStats.CpuDetailedStats.Nice)
	applianceStatsCpuDetailedStatsSoftIrq.Set(a.ApplianceStats.CpuDetailedStats.SoftIrq)
	applianceStatsCpuDetailedStatsSteal.Set(a.ApplianceStats.CpuDetailedStats.Steal)
	applianceStatsCpuDetailedStatsSystem.Set(a.ApplianceStats.CpuDetailedStats.System)
	applianceStatsCpuDetailedStatsUser.Set(a.ApplianceStats.CpuDetailedStats.User)

	//	fmt.Println(a)
	//	urlTarget := "https://" + args.IPAddr + "/api/types/System/instances/action/querySelectedStatistics"
	//
	//	client := &http.Client{
	//		Transport: &http.Transport{
	//			TLSClientConfig: &tls.Config{
	//				InsecureSkipVerify: args.Insecure,
	//			},
	//		},
	//	}

	//	query := `{"properties":["maxCapacityInKb", "capacityInUseInKb", "thinCapacityInUseInKb"]}`
	//
	//	for {
	//
	//		token := getToken(args)
	//
	//		var p capacityMetrics
	//		req, err := http.NewRequest("POST", urlTarget, bytes.NewBuffer([]byte(query)))
	//		if err != nil {
	//			log.Fatal(err)
	//		}
	//
	//		req.Header.Set("Content-Type", "application/json")
	//		req.Header.Set("Authorization", "Basic "+basicAuth("", string(token)))
	//
	//		resp, err := client.Do(req)
	//		if err != nil {
	//			log.Fatal(err)
	//		}
	//
	//		body, error := ioutil.ReadAll(resp.Body)
	//		if error != nil {
	//			log.Fatal(error)
	//		}
	//
	//		err = json.Unmarshal(body, &p)
	//		if err != nil {
	//			log.Println(err)
	//		}
	//
	//		capacityInUseInKb.Set(p.CapacityInUseInKb)
	//		thinCapacityInUseInKb.Set(p.ThinCapacityInUseInKb)
	//		maxCapacityInKb.Set(p.MaxCapacityInKb)
	//
	//		time.Sleep(time.Duration(args.Refresh) * time.Second)
	//	}
}

//func getToken(args *Args) (token []byte) {
//	urlTarget := "https://" + args.IPAddr + "/api/login"
//	username := args.Username
//	password := args.Password
//	client := &http.Client{
//		Transport: &http.Transport{
//			TLSClientConfig: &tls.Config{
//				InsecureSkipVerify: args.Insecure,
//			},
//		},
//	}
//	req, err := http.NewRequest("GET", urlTarget, nil)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	req.SetBasicAuth(username, password)
//
//	resp, err := client.Do(req)
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer resp.Body.Close()
//
//	token, err = ioutil.ReadAll(resp.Body)
//	if err != nil {
//		log.Fatal(err)
//	}
//	return
//}

// maybe this function can be deleted.
//func basicAuth(username, password string) string {
//	auth := username + ":" + password
//	return base64.StdEncoding.EncodeToString([]byte(strings.Replace(auth, "\"", "", -1)))
//}
