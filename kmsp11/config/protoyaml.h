#ifndef KMSP11_CONFIG_PROTOYAML_H_
#define KMSP11_CONFIG_PROTOYAML_H_

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "google/protobuf/message.h"
#include "yaml-cpp/yaml.h"

namespace kmsp11 {

// Parse the supplied YAML node into the provided protobuf message. The message
// descriptor of the supplied protobuf message supplies the parsing rules.
//
// The protobuf scalar types string, int32, and bool are supported. Message
// fields and repeated message fields are also supported.
//
// For example, given these protobuf message descriptors:
//
// message SampleMessage {
//   string string_value = 1;
//   bool bool_value = 2;
//   repeated KeyValue nested_values = 3;
// }
//
// message KeyValue {
//   int32 key = 1;
//   string value = 2;
// }
//
// We would translate the following YAML file:
//
// bool_value: false
// nested_values:
//   - key: 123
//     value: foo
//   - value: bar
//   - key: 456
//
// Into an equivalent protobuf representation:
//
// bool_value: false
// nested_values {
//   key: 123
//   value: "foo"
// }
// nested_values {
//   value: "bar"
// }
// nested_values {
//   key: 456
// }
//
// Note that all values are always optional.
//
// YAML that is inconsistent with the protobuf descriptor results in an
// InvalidArgument error. Unsupported field types in the protobuf message
// descriptor result in an Internal error.
absl::Status YamlToProto(const YAML::Node& node,
                         google::protobuf::Message* message);

}  // namespace kmsp11

#endif  // KMSP11_CONFIG_PROTOYAML_H_
