package fakekms

import (
	"github.com/golang/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

type protoWhitelister map[string]struct{}

func whitelist(paths ...string) protoWhitelister {
	p := make(protoWhitelister)
	for _, path := range paths {
		p[path] = struct{}{}
	}
	return p
}

func (w protoWhitelister) check(msg proto.GeneratedMessage) error {
	return w.checkInternal("", proto.MessageV2(msg).ProtoReflect())
}

func (w protoWhitelister) checkInternal(prefix string, msg protoreflect.Message) (err error) {
	if len(msg.GetUnknown()) > 0 {
		return errUnimplemented("message contains unknown fields")
	}

	if prefix != "" {
		prefix += "."
	}
	msg.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		path := prefix + string(fd.Name())

		if fd.Kind() == protoreflect.MessageKind { // if we have a nested message
			if _, ok := w[path]; ok {
				return true // the entire message is whitelisted; keep going
			}

			// otherwise check the nested message recursively
			err = w.checkInternal(path, v.Message())
			return err == nil // keep going if no error
		}

		// ensure the path is whitelisted
		_, ok := w[path]
		if !ok {
			err = errUnimplemented("field not supported: %s", path)
		}
		return ok // keep going if no error
	})
	return
}
