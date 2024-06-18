#network.tf
#vpc
resource "aws_vpc" "main" {
  cidr_block = "10.88.0.0/16"
  enable_dns_support = true
  enable_dns_hostnames = true
}

#subnet
resource "aws_subnet" "private-us-east-1a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.88.0.0/24"
  availability_zone = "us-east-1a"

  tags = {
    "Name"                            = "private-us-east-1a"
  }
}

resource "aws_subnet" "private-us-east-1b" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.88.32.0/24"
  availability_zone = "us-east-1b"

  tags = {
    "Name"                            = "private-us-east-1b"
  }
}

resource "aws_subnet" "public-us-east-1a" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.88.64.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = true

  tags = {
    "Name"               = "public-us-east-1a"
  }
}

resource "aws_subnet" "public-us-east-1b" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.88.96.0/24"
  availability_zone       = "us-east-1b"
  map_public_ip_on_launch = true

  tags = {
    "Name"                = "public-us-east-1b"
  }
}

# iam role for eks cluster
resource "aws_iam_role" "demo" {
  name = "eks-cluster-demo"

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "eks.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "demo-AmazonEKSClusterPolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.demo.name
}


resource "aws_security_group" "cluster" {
  name        = "eks-cluster-sg"
  description = "k8s masters"
  vpc_id      = aws_vpc.main.id
 
}


resource "aws_security_group_rule" "cluster-api" {
  security_group_id        = aws_security_group.cluster.id
  type                     = "ingress"
  protocol                 = "tcp"
  from_port                = 0
  to_port                  = 65535
  cidr_blocks              = ["0.0.0.0/0"]
  description              = "Allow API traffic from k8s nodes"
}

resource "aws_security_group_rule" "cluster-kubelet" {
  security_group_id        = aws_security_group.cluster.id
  type                     = "egress"
  protocol                 = "-1"
  from_port                = 0
  to_port                  = 0
  cidr_blocks              = ["0.0.0.0/0"]
  description              = "Allow kubelet traffic to k8s nodes"
}


resource "aws_security_group" "nodes" {
  name        = "eks-node"
  description = "k8s nodes"
  vpc_id      = aws_vpc.main.id
  
}

resource "aws_security_group_rule" "nodes-tcp" {
  security_group_id        = aws_security_group.nodes.id
  type                     = "ingress"
  protocol                 = "tcp"
  from_port                = 0
  to_port                  = 65535
  cidr_blocks             = ["0.0.0.0/0"]
  description              = "Allow TCP traffic between k8s nodes"
}

resource "aws_security_group_rule" "nodes-egress" {
  security_group_id = aws_security_group.nodes.id
  type              = "egress"
  protocol          = -1
  from_port         = 0
  to_port           = 0
  cidr_blocks       = ["0.0.0.0/0"]
  description       = "Allow all outgoing traffic"
}
