// Copyright 2022 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "gematria/basic_block/basic_block_protos.h"

#include <algorithm>
#include <iterator>
#include <string>
#include <vector>

#include "gematria/basic_block/basic_block.h"
#include "gematria/proto/canonicalized_instruction.pb.h"
#include "google/protobuf/repeated_ptr_field.h"

namespace gematria {

namespace {
  std::vector<std::string> ToVector(
    const google::protobuf::RepeatedPtrField<std::string>& protos) {
  return std::vector<std::string>(protos.begin(), protos.end());
  }
}

AddressTuple AddressTupleFromProto(
    const CanonicalizedOperandProto::AddressTuple& proto) {
  return AddressTuple(
      /* base_register = */ proto.base_register().physical_register(),
      /* displacement = */ proto.displacement(),
      /* index_register = */ proto.index_register().physical_register(),
      /* scaling = */ proto.scaling(),
      /* segment_register = */ proto.segment().physical_register());
}

CanonicalizedOperandProto::AddressTuple ProtoFromAddressTuple(
    const AddressTuple& address_tuple) {
  CanonicalizedOperandProto::AddressTuple proto;
  proto.mutable_base_register()->set_physical_register(
      address_tuple.base_register);
  proto.set_displacement(address_tuple.displacement);
  proto.mutable_index_register()->set_physical_register(
      address_tuple.index_register);
  proto.set_scaling(address_tuple.scaling);
  proto.mutable_segment()->set_physical_register(
      address_tuple.segment_register);
  return proto;
}

InstructionOperand InstructionOperandFromProto(
    const CanonicalizedOperandProto& proto) {
  auto register_proto = proto.register_();
  switch (proto.operand_case()) {
    case CanonicalizedOperandProto::OPERAND_NOT_SET:
      return InstructionOperand();
    case CanonicalizedOperandProto::kRegister:
      {
        switch (register_proto.type_case()) {
          case CanonicalizedOperandProto::RegisterProto::TYPE_NOT_SET:
            return InstructionOperand();
          case CanonicalizedOperandProto::RegisterProto::kPhysicalRegister:
            return InstructionOperand::Register(
                register_proto.physical_register());
          case CanonicalizedOperandProto::RegisterProto::kVirtualRegister:
            return InstructionOperand::VirtualRegister(
                register_proto.virtual_register().name(),
                register_proto.virtual_register().size(),
                ToVector(register_proto.virtual_register().intefered_register()));
        }
        return InstructionOperand();
      }
    case CanonicalizedOperandProto::kImmediateValue:
      return InstructionOperand::ImmediateValue(proto.immediate_value());
    case CanonicalizedOperandProto::kFpImmediateValue:
      return InstructionOperand::FpImmediateValue(proto.fp_immediate_value());
    case CanonicalizedOperandProto::kAddress:
      return InstructionOperand::Address(
          AddressTupleFromProto(proto.address()));
    case CanonicalizedOperandProto::kMemory:
      return InstructionOperand::MemoryLocation(
          proto.memory().alias_group_id());
  }
}

CanonicalizedOperandProto ProtoFromInstructionOperand(
    const InstructionOperand& operand) {
  CanonicalizedOperandProto proto;
  CanonicalizedOperandProto::RegisterProto register_proto;
  switch (operand.type()) {
    case OperandType::kRegister:
      register_proto.set_physical_register(operand.register_name());
      *proto.mutable_register_() = register_proto;
      break;
    case OperandType::kImmediateValue:
      proto.set_immediate_value(operand.immediate_value());
      break;
    case OperandType::kFpImmediateValue:
      proto.set_fp_immediate_value(operand.fp_immediate_value());
      break;
    case OperandType::kAddress:
      *proto.mutable_address() = ProtoFromAddressTuple(operand.address());
      break;
    case OperandType::kMemory:
      proto.mutable_memory()->set_alias_group_id(operand.alias_group_id());
      break;
    case OperandType::kVirtualRegister: {
      auto virtual_register =
          register_proto.mutable_virtual_register();
      virtual_register->set_name(operand.register_name());
      virtual_register->set_size(operand.size());
      *proto.mutable_register_() = register_proto;
      break;
    }
    case OperandType::kUnknown:
      break;
  }
  return proto;
}

namespace {
std::vector<InstructionOperand> ToVector(
    const google::protobuf::RepeatedPtrField<CanonicalizedOperandProto>&
        protos) {
  std::vector<InstructionOperand> result(protos.size());
  std::transform(protos.begin(), protos.end(), result.begin(),
                 InstructionOperandFromProto);
  return result;
}

void ToRepeatedPtrField(
    const std::vector<InstructionOperand>& operands,
    google::protobuf::RepeatedPtrField<CanonicalizedOperandProto>*
        repeated_field) {
  repeated_field->Reserve(operands.size());
  std::transform(operands.begin(), operands.end(),
                 google::protobuf::RepeatedFieldBackInserter(repeated_field),
                 ProtoFromInstructionOperand);
}

}  // namespace

Instruction InstructionFromProto(const CanonicalizedInstructionProto& proto) {
  return Instruction(
      /* mnemonic = */ proto.mnemonic(),
      /* llvm_mnemonic = */ proto.llvm_mnemonic(),
      /* prefixes = */
      std::vector<std::string>(proto.prefixes().begin(),
                               proto.prefixes().end()),
      /* input_operands = */ ToVector(proto.input_operands()),
      /* implicit_input_operands = */ ToVector(proto.implicit_input_operands()),
      /* output_operands = */ ToVector(proto.output_operands()),
      /* implicit_output_operands = */
      ToVector(proto.implicit_output_operands()));
}

CanonicalizedInstructionProto ProtoFromInstruction(
    const Instruction& instruction) {
  CanonicalizedInstructionProto proto;
  proto.set_mnemonic(instruction.mnemonic);
  proto.set_llvm_mnemonic(instruction.llvm_mnemonic);
  proto.mutable_prefixes()->Assign(instruction.prefixes.begin(),
                                   instruction.prefixes.end());
  ToRepeatedPtrField(instruction.input_operands,
                     proto.mutable_input_operands());
  ToRepeatedPtrField(instruction.implicit_input_operands,
                     proto.mutable_implicit_input_operands());
  ToRepeatedPtrField(instruction.output_operands,
                     proto.mutable_output_operands());
  ToRepeatedPtrField(instruction.implicit_output_operands,
                     proto.mutable_implicit_output_operands());
  return proto;
}

namespace {

std::vector<Instruction> ToVector(
    const google::protobuf::RepeatedPtrField<CanonicalizedInstructionProto>&
        protos) {
  std::vector<Instruction> result(protos.size());
  std::transform(protos.begin(), protos.end(), result.begin(),
                 InstructionFromProto);
  return result;
}

}  // namespace

BasicBlock BasicBlockFromProto(const BasicBlockProto& proto) {
  return BasicBlock(
      /* instructions = */ ToVector(proto.canonicalized_instructions()));
}

}  // namespace gematria
