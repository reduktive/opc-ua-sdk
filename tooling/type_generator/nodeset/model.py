# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict


class NodeClass(str, Enum):
    object = "Object"
    variable = "Variable"
    method = "Method"


class ModellingRule(str, Enum):
    mandatory = "Mandatory"
    optional = "Optional"
    # Placeholder rules (Part 3 section 6.4.2): the declaration is a *template* for
    # zero-or-more server-chosen-name children. Instance-handle emitters skip
    # these - there is no fixed browse-name to expose as an accessor; callers
    # must enumerate dynamic children at runtime.
    mandatory_placeholder = "MandatoryPlaceholder"
    optional_placeholder = "OptionalPlaceholder"
    none = "None"


class UaMethodArgument(BaseModel):
    """An argument of a UAMethod (from InputArguments/OutputArguments Value)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    symbolic_name: str | None = None  # C++-safe spelling from <Argument> SymbolicName, if any
    data_type: str  # DataType NodeId (e.g. "i=7" for UInt32)
    value_rank: int = -1  # -1 = scalar


class UaChildDeclaration(BaseModel):
    """A child node declared under a UAObjectType or UAVariableType."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    node_id: str
    browse_name: str
    symbolic_name: str | None = None  # C++-safe spelling from SymbolicName attr, if any
    node_class: NodeClass
    data_type: str | None = None
    value_rank: int | None = None
    type_definition_id: str | None = None
    reference_type: str
    modelling_rule: ModellingRule
    input_arguments: list[UaMethodArgument] = []
    output_arguments: list[UaMethodArgument] = []


class UaTypeDefinitionNode(BaseModel):
    """Base for UAObjectType and UAVariableType nodes."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    node_id: str
    browse_name: str
    symbolic_name: str | None = None  # C++-safe spelling from SymbolicName attr, if any
    is_abstract: bool = False
    parent_type_id: str | None = None
    type_node_class: str = "ObjectType"  # "ObjectType" or "VariableType"
    category: str | None = None  # <Category> element from NodeSet XML
    children: list[UaChildDeclaration] = []
    source_nodeset: str | None = None  # absolute path of the owning NodeSet XML


class UaDataTypeRef(BaseModel):
    """Minimal `UADataType` identification extracted from a NodeSet."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    node_id: str
    browse_name: str


class UaDataTypeNode(BaseModel):
    """`UADataType` with minimal hierarchy information for subtype checks."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    node_id: str
    browse_name: str
    parent_node_id: str | None = None
    source_nodeset: str | None = None
    is_abstract: bool = False
    category: str | None = None


class UaDataTypeField(BaseModel):
    """Field entry within a `UADataType/Definition`.

    NodeSet `Field` is used for both:
    - enumeration/option-set values (`Name` + `Value`), and
    - structure fields (`Name` + `DataType` + `ValueRank` + `IsOptional` ...).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    symbolic_name: str | None = None  # C++-safe spelling from <Field> SymbolicName attr, if any
    value: int | None = None
    data_type: str | None = None
    value_rank: int | None = None
    is_optional: bool | None = None
    allow_subtypes: bool | None = None
    description: str | None = None  # <Field><Description> text, where the NodeSet supplies one


class UaDataTypeDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str | None = None
    is_option_set: bool = False
    is_union: bool = False
    fields: list[UaDataTypeField]


class UaDataTypeNodeWithDefinition(UaDataTypeNode):
    model_config = ConfigDict(extra="forbid", frozen=True)

    definition: UaDataTypeDefinition | None = None
