package cloudformation

import (
	"encoding/json"
)

// AWSAutoScalingScalingPolicy_MetricDimension AWS CloudFormation Resource (AWS::AutoScaling::ScalingPolicy.MetricDimension)
// See: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-scalingpolicy-metricdimension.html
type AWSAutoScalingScalingPolicy_MetricDimension struct {

	// Name AWS CloudFormation Property
	// Required: true
	// See: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-scalingpolicy-metricdimension.html#cfn-autoscaling-scalingpolicy-metricdimension-name
	Name *Value `json:"Name,omitempty"`

	// Value AWS CloudFormation Property
	// Required: true
	// See: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-scalingpolicy-metricdimension.html#cfn-autoscaling-scalingpolicy-metricdimension-value
	Value *Value `json:"Value,omitempty"`
}

// AWSCloudFormationType returns the AWS CloudFormation resource type
func (r *AWSAutoScalingScalingPolicy_MetricDimension) AWSCloudFormationType() string {
	return "AWS::AutoScaling::ScalingPolicy.MetricDimension"
}

func (r *AWSAutoScalingScalingPolicy_MetricDimension) MarshalJSON() ([]byte, error) {
	return json.Marshal(*r)
}
