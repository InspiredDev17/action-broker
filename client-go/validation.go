package actionbroker

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

func validateCapabilityArguments(kind CapabilityKind, arguments any) error {
	switch kind {
	case CapabilityReadFile:
		value := arguments.(ReadFileInput)
		return validateRootedPath(value.Path)
	case CapabilityWriteFile:
		value := arguments.(WriteFileInput)
		if err := validateRootedPath(value.Path); err != nil {
			return err
		}
		return validateBase64(value.ContentBase64)
	case CapabilityCreateFile:
		value := arguments.(CreateFileInput)
		if err := validateRootedPath(value.Path); err != nil {
			return err
		}
		return validateBase64(value.ContentBase64)
	case CapabilityMoveFile:
		value := arguments.(MoveFileInput)
		if err := validateRootedPath(value.Source); err != nil {
			return fmt.Errorf("source: %w", err)
		}
		return validateRootedPath(value.Destination)
	case CapabilityDeleteFile:
		return validateRootedPath(arguments.(DeleteFileInput).Path)
	case CapabilityListDirectory:
		return validateRootedPath(arguments.(ListDirectoryInput).Path)
	case CapabilityExecuteApprovedCommand:
		return validateApprovedCommand(arguments.(ExecuteApprovedCommandInput))
	case CapabilityGitRead:
		value := arguments.(GitReadInput)
		if err := validateRootedPath(value.RepositoryPath); err != nil {
			return err
		}
		return validateMarshaling(value.Operation)
	case CapabilityGitWrite:
		value := arguments.(GitWriteInput)
		if err := validateRootedPath(value.RepositoryPath); err != nil {
			return err
		}
		return validateMarshaling(value.Operation)
	case CapabilityHTTPRequest:
		return validateHTTPRequest(arguments.(HTTPRequestInput))
	case CapabilityBrowserAction:
		value := arguments.(BrowserActionInput)
		if strings.TrimSpace(value.BrowserSessionID) == "" {
			return fmt.Errorf("browser session ID is required")
		}
		if value.Operation.kind == BrowserNavigate {
			if err := validateHTTPURL(value.Operation.url); err != nil {
				return err
			}
		}
		return validateMarshaling(value.Operation)
	case CapabilityProcessInspect:
		return validateMarshaling(arguments.(ProcessInspectInput).Operation)
	case CapabilityServiceInspect:
		return requireNonempty("service name", arguments.(ServiceInspectInput).ServiceName)
	case CapabilityServiceControl:
		value := arguments.(ServiceControlInput)
		if err := requireNonempty("service name", value.ServiceName); err != nil {
			return err
		}
		switch value.Operation {
		case ServiceStart, ServiceStop, ServiceRestart, ServiceReload:
			return nil
		default:
			return fmt.Errorf("unknown service control operation %q", value.Operation)
		}
	case CapabilityContainerAction:
		value := arguments.(ContainerActionInput)
		if value.Runtime != ContainerDocker && value.Runtime != ContainerPodman {
			return fmt.Errorf("unknown container runtime %q", value.Runtime)
		}
		if err := requireNonempty("container ID", value.ContainerID); err != nil {
			return err
		}
		switch value.Operation {
		case ContainerInspect, ContainerStart, ContainerStop, ContainerRestart, ContainerPause, ContainerUnpause:
			return nil
		default:
			return fmt.Errorf("unknown container operation %q", value.Operation)
		}
	case CapabilityNodeAction:
		value := arguments.(NodeActionInput)
		if err := requireNonempty("node ID", value.NodeID); err != nil {
			return err
		}
		switch value.Operation {
		case NodeInspectStatus, NodeDrain, NodeResume, NodeRestartRuntime:
			return nil
		default:
			return fmt.Errorf("unknown node operation %q", value.Operation)
		}
	default:
		return fmt.Errorf("unknown capability %q", kind)
	}
}

func validateCapabilityResult(kind CapabilityKind, result any) error {
	if !outputTypeMatches(kind, result) {
		return fmt.Errorf("result does not match capability %q", kind)
	}
	switch kind {
	case CapabilityReadFile:
		value := result.(ReadFileOutput)
		if err := validateRootedPath(value.Path); err != nil {
			return err
		}
		if err := validateBase64(value.ContentBase64); err != nil {
			return err
		}
		if !validLowerHex(value.SHA256, 32) {
			return fmt.Errorf("read output digest is invalid")
		}
	case CapabilityWriteFile, CapabilityCreateFile:
		value := result.(FileMutationOutput)
		if err := validateRootedPath(value.Path); err != nil {
			return err
		}
		if !validLowerHex(value.CurrentSHA256, 32) {
			return fmt.Errorf("file mutation digest is invalid")
		}
	case CapabilityMoveFile:
		value := result.(MoveFileOutput)
		if err := validateRootedPath(value.Source); err != nil {
			return err
		}
		if err := validateRootedPath(value.Destination); err != nil {
			return err
		}
		if !validLowerHex(value.MovedSHA256, 32) {
			return fmt.Errorf("move output digest is invalid")
		}
	case CapabilityDeleteFile:
		value := result.(DeleteFileOutput)
		if err := validateRootedPath(value.Path); err != nil {
			return err
		}
		if !validLowerHex(value.PreviousSHA256, 32) {
			return fmt.Errorf("delete output digest is invalid")
		}
	case CapabilityListDirectory:
		if err := validateRootedPath(result.(ListDirectoryOutput).Path); err != nil {
			return err
		}
	case CapabilityGitRead:
		if err := validateRootedPath(result.(GitReadOutput).RepositoryPath); err != nil {
			return err
		}
	case CapabilityGitWrite:
		if err := validateRootedPath(result.(GitWriteOutput).RepositoryPath); err != nil {
			return err
		}
	case CapabilityHTTPRequest:
		value := result.(HTTPRequestOutput)
		if err := validateHTTPURL(value.FinalURL); err != nil {
			return err
		}
		if err := validateBase64(value.BodyBase64); err != nil {
			return err
		}
	case CapabilityBrowserAction:
		if err := requireNonempty("browser session ID", result.(BrowserActionOutput).BrowserSessionID); err != nil {
			return err
		}
	case CapabilityServiceInspect:
		if err := requireNonempty("service name", result.(ServiceInspectOutput).ServiceName); err != nil {
			return err
		}
	case CapabilityServiceControl:
		if err := requireNonempty("service name", result.(ServiceControlOutput).ServiceName); err != nil {
			return err
		}
	case CapabilityContainerAction:
		if err := requireNonempty("container ID", result.(ContainerActionOutput).ContainerID); err != nil {
			return err
		}
	case CapabilityNodeAction:
		if err := requireNonempty("node ID", result.(NodeActionOutput).NodeID); err != nil {
			return err
		}
	}
	return nil
}

func validateRootedPath(value RootedPath) error {
	if err := validateIdentifier("root ID", value.RootID); err != nil {
		return err
	}
	if value.RelativePath == "" || strings.ContainsRune(value.RelativePath, 0) {
		return fmt.Errorf("relative path is invalid")
	}
	if strings.HasPrefix(value.RelativePath, "/") {
		return fmt.Errorf("absolute path is forbidden")
	}
	for _, component := range strings.Split(value.RelativePath, "/") {
		if component == ".." {
			return fmt.Errorf("parent traversal is forbidden")
		}
	}
	return nil
}

func validateApprovedCommand(value ExecuteApprovedCommandInput) error {
	if err := validateIdentifier("approved program ID", value.ProgramID); err != nil {
		return err
	}
	if err := validateRootedPath(value.WorkingDirectory); err != nil {
		return fmt.Errorf("working directory: %w", err)
	}
	if value.Arguments == nil || value.Environment == nil {
		return fmt.Errorf("arguments and environment must be explicit")
	}
	for _, argument := range value.Arguments {
		if strings.ContainsRune(argument, 0) {
			return fmt.Errorf("command argument contains a NUL byte")
		}
	}
	for name, environmentValue := range value.Environment {
		if !validEnvironmentName(name) || strings.ContainsRune(environmentValue, 0) {
			return fmt.Errorf("command environment contains a forbidden name or value")
		}
	}
	return nil
}

func validateHTTPRequest(value HTTPRequestInput) error {
	switch value.Method {
	case HTTPGet, HTTPHead, HTTPPost, HTTPPut, HTTPPatch, HTTPDelete:
	default:
		return fmt.Errorf("unknown HTTP method %q", value.Method)
	}
	if value.Headers == nil {
		return fmt.Errorf("HTTP headers must be explicit")
	}
	if err := validateHTTPURL(value.URL); err != nil {
		return err
	}
	if value.BodyBase64 != nil {
		return validateBase64(*value.BodyBase64)
	}
	return nil
}

func validateHTTPURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil || parsed.Fragment != "" {
		return fmt.Errorf("URL must be an absolute HTTP or HTTPS URL without credentials or fragment")
	}
	return nil
}

func validateBase64(value string) error {
	if _, err := base64.StdEncoding.DecodeString(value); err != nil {
		return fmt.Errorf("content is not canonical padded base64")
	}
	return nil
}

func validateMarshaling(value any) error {
	_, err := json.Marshal(value)
	return err
}

func validateIdentifier(kind, value string) error {
	if value == "" || len(value) > 128 {
		return fmt.Errorf("%s is invalid", kind)
	}
	for _, character := range []byte(value) {
		if !(character >= 'a' && character <= 'z') &&
			!(character >= 'A' && character <= 'Z') &&
			!(character >= '0' && character <= '9') &&
			character != '-' && character != '_' && character != '.' {
			return fmt.Errorf("%s is invalid", kind)
		}
	}
	return nil
}

func requireNonempty(kind, value string) error {
	if strings.TrimSpace(value) == "" || strings.ContainsRune(value, 0) {
		return fmt.Errorf("%s is required", kind)
	}
	return nil
}

func validEnvironmentName(name string) bool {
	if name == "" || len(name) > 64 || name == "PATH" || name == "IFS" || name == "ENV" || name == "BASH_ENV" || strings.HasPrefix(name, "LD_") || strings.HasPrefix(name, "DYLD_") {
		return false
	}
	for index, character := range []byte(name) {
		if character == '_' || character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || index > 0 && character >= '0' && character <= '9' {
			continue
		}
		return false
	}
	return true
}
