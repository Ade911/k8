# prodivder 

# 1-provider.tf
provider "aws" {
     region = "us-east-1"
}

terraform {
  required_providers {
    aws = {
        source = "hashicorp/aws"
        version = "~> 3.0"
    }
  }
}


# 2 VPC.tf

resource "aws_vpc" "main" {
    cidr_block = "10.0.0.0/16"

    tags = {
      Name = "main"
    } 
}

# 3 igw.tf
# Create an Internet Gateway for the VPC
/*resource "aws_internet_gateway" "main_igw" {
  vpc_id = aws_vpc.main_vpc.id
  tags = {
    Name = "main-igw"
  }
}*/

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "igw"
  }
}


# 4 subnet.tf
# create two public and two private subnet in different availability zones

# Create a private subnet within the VPC
# you can use shared instead of owned if you are sharing kubernetes with another service
resource "aws_subnet" "private-us-east-1a" {
  vpc_id = aws_vpc.main.id
  cidr_block = "10.0.0.0/19"
  availability_zone = "us-east-1a"

  tags = {
    "Name"                               = "private-us-east-1a"
    "kubernetes.io/role/internal-elb"    = "1"
    "kubernetes.io/cluster/demo"         = "owned"
  }
}


resource "aws_subnet" "private-us-east-1b" {
  vpc_id = aws_vpc.main.id
  cidr_block = "10.0.32.0/19"
  availability_zone = "us-east-1b"

  tags = {
    "Name"                               = "private-us-east-1b"
    "kubernetes.io/role/internal-elb"    = "1"
    "kubernetes.io/cluster/demo"         = "owned"
  }
}


# Create a public subnet within the VPC
# map_public_ip_on_launch = true only if you want to creat public k8 instance group
# "kubernetes.io/role/internal-elb"    = "1" this instructs k8 to create public load balancer in these subnets

resource "aws_subnet" "public-us-east-1a" {
  vpc_id = aws_vpc.main.id
  cidr_block = "10.0.64.0/19"
  availability_zone = "us-east-1a"
  map_public_ip_on_launch = true
  
  tags = {
    Name = "public-subnet"
     "Name"                              = "public-us-east-1a"
    "kubernetes.io/role/internal-elb"    = "1"
    "kubernetes.io/cluster/demo"         = "owned"
  }
}

resource "aws_subnet" "public-us-east-1b" {
  vpc_id = aws_vpc.main.id
  cidr_block = "10.0.96.0/19"
  availability_zone = "us-east-1b"
  map_public_ip_on_launch = true
  
  tags = {
    Name = "public-subnet"
     "Name"                              = "public-us-east-1b"
    "kubernetes.io/role/internal-elb"    = "1"
    "kubernetes.io/cluster/demo"         = "owned"
  }
}

# 5 natgw.tf
resource "aws_eip" "nat" {
    tags = {
        Name = "nat"
    }
  
}


resource "aws_nat_gateway" "nat" {
 allocation_id = aws_eip.nat.id
 subnet_id = aws_subnet.public-us-east-1a.id

 tags = {
    Name = "nat"
 }

depends_on = [aws_internet_gateway.igw]
}

# 6 routetable.tf
# i do private routing table with a default route to nat gateway

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  route = [
    {
      cidr_block                 = "0.0.0.0/0"
      nat_gateway_id             = aws_nat_gateway.nat.id
      carrier_gateway_id         = ""
      destination_prefix_list_id = ""
      egress_only_gateway_id     = ""
      gateway_id                 = ""
      instance_id                = ""
      ipv6_cidr_block            = ""
      local_gateway_id           = ""
      network_interface_id       = ""
      transit_gateway_id         = ""
      vpc_endpoint_id            = ""
      vpc_peering_connection_id  = ""
    },
  ]

  tags = {
    Name = "private"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route = [
    {
      cidr_block                 = "0.0.0.0/0"
      gateway_id                 = aws_internet_gateway.igw.id
      nat_gateway_id             = ""
      carrier_gateway_id         = ""
      destination_prefix_list_id = ""
      egress_only_gateway_id     = ""
      instance_id                = ""
      ipv6_cidr_block            = ""
      local_gateway_id           = ""
      network_interface_id       = ""
      transit_gateway_id         = ""
      vpc_endpoint_id            = ""
      vpc_peering_connection_id  = ""
    },
  ]

  tags = {
    Name = "public"
  }
}

resource "aws_route_table_association" "private-us-east-1a" {
  subnet_id      = aws_subnet.private-us-east-1a.id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "private-us-east-1b" {
  subnet_id      = aws_subnet.private-us-east-1b.id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "public-us-east-1a" {
  subnet_id      = aws_subnet.public-us-east-1a.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public-us-east-1b" {
  subnet_id      = aws_subnet.public-us-east-1b.id
  route_table_id = aws_route_table.public.id
}


/*resource "aws_route_table" "private" {
    vpc_id = aws_vpc.main.id

    route = [
        {
            cidr_block =  "0.0.0.0/0"
            gateway_id = aws_nat_gateway.nat.id
            nat_gateway_id = ""
            carrier_gateway_id = ""
            destination_prefix_list_id = ""
            egress_only_gateway_id = ""
            gateway_id = ""
            instance_id = ""
            ipv6_cidr_block = ""
            local_gateway_id = ""
            network_interface_id = ""
            transit_gateway_id = ""
            vpc_endpoint_id = ""
            vpc_peering_connection_id = ""
        },
    ]
  
  tags = {
    Name = "private"
  }
}


# i do public routing table with a default route to internet gateway

resource "aws_route_table" "public" {
    vpc_id = aws_vpc.main.id

    route = [
        {
            cidr_block =  "0.0.0.0/0"
            nat_gateway_id = aws_internet_gateway.igw.id
            carrier_gateway_id = ""
            destination_prefix_list_id = ""
            egress_only_gateway_id = ""
            gateway_id = ""
            instance_id = ""
            ipv6_cidr_block = ""
            local_gateway_id = ""
            network_interface_id = ""
            transit_gateway_id = ""
            vpc_endpoint_id = ""
            vpc_peering_connection_id = ""
        },
    ]
  
  tags = {
    Name = "public"
  }
}


# i associated subnets with routing tables, by creating table association resources for all 4 subnets

resource "aws_route_table_association" "private-us-east-1a" {
  subnet_id    = aws_subnet.private-us-east-1a.id
  route_table_id = aws_route_table.private.id

}


resource "aws_route_table_association" "private-us-east-1b" {
  subnet_id    = aws_subnet.private-us-east-1b
  route_table_id = aws_route_table.private.id

}


resource "aws_route_table_association" "public-us-east-1a" {
  subnet_id    = aws_subnet.public-us-east-1a
  route_table_id = aws_route_table.public.id

}


resource "aws_route_table_association" "public-us-east-1b" {
  subnet_id    = aws_subnet.public-us-east-1b
  route_table_id = aws_route_table.public.id

}*/

# 7 eks.tf
# eks makes call to other AWS services on your behalf to manage resources that you use with the service eg eks will create an autoscaling group for each instance group if you use managed nodes

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

resource "aws_eks_cluster" "demo" {
  name     = "demo"
  role_arn = aws_iam_role.demo.arn

  vpc_config {
    subnet_ids = [
      aws_subnet.private-us-east-1a.id,
      aws_subnet.private-us-east-1b.id,
      aws_subnet.public-us-east-1a.id,
      aws_subnet.public-us-east-1b.id
    ]
  }

  depends_on = [aws_iam_role_policy_attachment.demo-AmazonEKSClusterPolicy]
}







/*resource "aws_iam_role" "demo" {
 name = "eks-cluster-demo"

 assume_role_policy = <<POLICY
{
 "Version": 2012-10-17",
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

resource "aws_eks_cluster" "demo" {
    name = "demo"
    role_arn = aws_iam_role.demo.arn

    vpc_config {
      subnet_ids = [
        aws_subnet.private-us-east-1a.id,
        aws_subnet.private-us-east-1b.id,
        aws_subnet.public-us-east-1a.id,
        aws_subnet.public-us-east-1b.id
      ]
  }

 depends_on = [aws_iam_role_policy_attachment.demo-AmazonEKSClusterPolicy] 
  
}*/

# 8 nodes.tf
 resource "aws_iam_role" "nodes" {
    name = "eks-node-group-nodes"
    
    assume_role_policy = jsonencode({
        Statement = [{
            Action = "sts:AssumeRole"
            Effect = "Allow"
            Principal = {
                Service ="ec2.amazonaws.com"
            }
        }]
        Version = "2012-10-17"
    })
  
}


# I added some policies to the node
# Workernode policy : amazon eks node kubelet daemon makes aws APIs calls it grant access to ec2 and eks
# CNI policy
# AmazonEC2ContainerRegistryReadOnly: It allows to download and run docker images from the ECR repository

resource "aws_iam_role_policy_attachment" "nodes-AmazonEKSWorkerNodePolicy" {
    policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
    role       = aws_iam_role.nodes.name 
}

resource "aws_iam_role_policy_attachment" "nodes-AmazonEKS_CNI_Policy" {
    policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
    role       = aws_iam_role.nodes.name 
}

resource "aws_iam_role_policy_attachment" "nodes-AmazonEC2ContainerRegistryReadOnly" {
    policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
    role       = aws_iam_role.nodes.name 
}


resource "aws_eks_node_group" "private-nodes" {
  cluster_name = aws_eks_cluster.demo.name
  node_group_name =  "private-nodes"
  node_role_arn = aws_iam_role.nodes.arn

  subnet_ids = [
    aws_subnet.private-us-east-1a.id,
    aws_subnet.private-us-east-1b.id
    ]
    capacity_type = "ON_DEMAND"
    instance_types = ["t3.small"]

# define the min and max number of nodes so that EKS cluster will autoscale the nodes, the auto scaler will adjust the desired size based on the load
    scaling_config {
      desired_size = 1
      max_size = 5
      min_size = 0
    }

    update_config {
      max_unavailable = 1
    }

    labels = {
      role = "general"
    }
 
  depends_on = [
    aws_iam_role_policy_attachment.nodes-AmazonEKSWorkerNodePolicy,
    aws_iam_role_policy_attachment.nodes-AmazonEKS_CNI_Policy,
    aws_iam_role_policy_attachment.nodes-AmazonEC2ContainerRegistryReadOnly,
  ]
}


/*  depends_on = [
    aws_iam_role_policy_attachment.nodes-AmazonEKSWorkerNodePolicy,
    aws_iam_role_policy_attachment.nodes-AmazonEKS_CNI_Policy,
    aws_iam_role_policy_attachment.nodes-AmazonEC2ContainerRegistryReadOnly,
  ]*/

# 9 iam-oidc.tf
# to manage permissions for applications deployed in kubernetes, i can attach policies to k8 nodes directly, this enables every pods get the same access to AWS resources but i am creating open ID provider for this purpose

data "tls_certificate" "eks" {
  url = aws_eks_cluster.demo.identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "eks" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.eks.certificates[0].sha1_fingerprint]
  url             = aws_eks_cluster.demo.identity[0].oidc[0].issuer
}

# 10 iam-test.tf
#  testing the provider first before deploying the autoscaller


data "aws_iam_policy_document" "test_oidc_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    condition {
      test     = "StringEquals"
      variable = "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:sub"
      values   = ["system:serviceaccount:default:aws-test"]
    }

    principals {
      identifiers = [aws_iam_openid_connect_provider.eks.arn]
      type        = "Federated"
    }
  }
}

resource "aws_iam_role" "test_oidc" {
  assume_role_policy = data.aws_iam_policy_document.test_oidc_assume_role_policy.json
  name               = "test-oidc"
}

# to test the provider, I am giving it S3 permission to list buckets

resource "aws_iam_policy" "test-policy" {
  name = "test-policy"

  policy = jsonencode({
    Statement = [{
      Action = [
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation"
      ]
      Effect   = "Allow"
      Resource = "arn:aws:s3:::*"
    }]
    Version = "2012-10-17"
  })
}

resource "aws_iam_role_policy_attachment" "test_attach" {
  role       = aws_iam_role.test_oidc.name
  policy_arn = aws_iam_policy.test-policy.arn
}

output "test_policy_arn" {
  value = aws_iam_role.test_oidc.arn
}

# 11-iam-autoscaler.tf
# i used OpenID connect provider to create an IAM role and bind it with the autoscaler
# Autoscaler will be deployed in the kube-system namespace
data "aws_iam_policy_document" "eks_cluster_autoscaler_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    condition {
      test     = "StringEquals"
      variable = "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:sub"
      values   = ["system:serviceaccount:kube-system:cluster-autoscaler"]
    }

    principals {
      identifiers = [aws_iam_openid_connect_provider.eks.arn]
      type        = "Federated"
    }
  }
}

# i then attach the eks-cluster autoscaler role
resource "aws_iam_role" "eks_cluster_autoscaler" {
  assume_role_policy = data.aws_iam_policy_document.eks_cluster_autoscaler_assume_role_policy.json
  name               = "eks-cluster-autoscaler"
}

# i grant access access to the autoscaling group to adjust thedesired size

resource "aws_iam_policy" "eks_cluster_autoscaler" {
  name = "eks-cluster-autoscaler"

  policy = jsonencode({
    Statement = [{
      Action = [
                "autoscaling:DescribeAutoScalingGroups",
                "autoscaling:DescribeAutoScalingInstances",
                "autoscaling:DescribeLaunchConfigurations",
                "autoscaling:DescribeTags",
                "autoscaling:SetDesiredCapacity",
                "autoscaling:TerminateInstanceInAutoScalingGroup",
                "ec2:DescribeLaunchTemplateVersions"
            ]
      Effect   = "Allow"
      Resource = "*"
    }]
    Version = "2012-10-17"
  })
}

# Then attached it to the same eks-cluster autoscaler role and output the ARN of the role to the terminal

resource "aws_iam_role_policy_attachment" "eks_cluster_autoscaler_attach" {
  role       = aws_iam_role.eks_cluster_autoscaler.name
  policy_arn = aws_iam_policy.eks_cluster_autoscaler.arn
}

output "eks_cluster_autoscaler_arn" {
  value = aws_iam_role.eks_cluster_autoscaler.arn
}

