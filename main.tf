provider "aws" {
    profile = "default"
    region = "ap-northeast-1"
}

resource "aws_vpc" "iida_hakone" {
    cidr_block           = "10.0.0.0/16"
    enable_dns_support   = true  # 自動でDSN名をつける
    enable_dns_hostnames = true

    tags = {
        Name = "iida-hakone"
    }
}

# public subnet
resource "aws_route_table" "iida_hakone_public" {
    vpc_id = aws_vpc.iida_hakone.id
}

resource "aws_internet_gateway" "iida_hakone_gateway" {
    vpc_id = aws_vpc.iida_hakone.id
}

resource "aws_route" "iida_hakone_public" {
    route_table_id         = aws_route_table.iida_hakone_public.id
    gateway_id             = aws_internet_gateway.iida_hakone_gateway.id
    destination_cidr_block = "0.0.0.0/0"
}

# public_0
resource "aws_subnet" "iida_hakone_public_0" {
    vpc_id     = aws_vpc.iida_hakone.id
    cidr_block = "10.0.1.0/24"
    map_public_ip_on_launch = true # このサブネットで上がってくるインスタンスに自動でIPをつける
    availability_zone = "ap-northeast-1a"
}

resource "aws_route_table_association" "iida_hakone_public_0" {
    subnet_id = aws_subnet.iida_hakone_public_0.id
    route_table_id = aws_route_table.iida_hakone_public.id
}

# public_1
resource "aws_subnet" "iida_hakone_public_1" {
    vpc_id     = aws_vpc.iida_hakone.id
    cidr_block = "10.0.2.0/24"
    map_public_ip_on_launch = true # このサブネットで上がってくるインスタンスに自動でIPをつける
    availability_zone = "ap-northeast-1c"
}

resource "aws_route_table_association" "iida_hakone_public_1" {
    subnet_id = aws_subnet.iida_hakone_public_1.id
    route_table_id = aws_route_table.iida_hakone_public.id
}

# private subnet

## private_0
resource "aws_subnet" "iida_hakone_private_0" {
    vpc_id                  = aws_vpc.iida_hakone.id
    cidr_block              = "10.0.65.0/24"
    availability_zone       = "ap-northeast-1a"
    map_public_ip_on_launch = false
}

resource "aws_eip" "iida_hakone_nat_gateway_0" {
    vpc        = true
    depends_on = [aws_internet_gateway.iida_hakone_gateway]
}

resource "aws_nat_gateway" "iida_hakone_nat_gateway_0" {
    allocation_id = aws_eip.iida_hakone_nat_gateway_0.id
    subnet_id     = aws_subnet.iida_hakone_public_0.id
    depends_on    = [aws_internet_gateway.iida_hakone_gateway]
}

resource "aws_route_table" "iida_hakone_private_0" {
    vpc_id = aws_vpc.iida_hakone.id
}

resource "aws_route" "iida_hakone_private_0" {
    route_table_id         = aws_route_table.iida_hakone_private_0.id
    nat_gateway_id         = aws_nat_gateway.iida_hakone_nat_gateway_0.id
    destination_cidr_block = "0.0.0.0/0"
}

resource "aws_route_table_association" "iida_hakone_private_0" {
    subnet_id      = aws_subnet.iida_hakone_private_0.id
    route_table_id = aws_route_table.iida_hakone_private_0.id
}

## private_1
resource "aws_subnet" "iida_hakone_private_1" {
    vpc_id                  = aws_vpc.iida_hakone.id
    cidr_block              = "10.0.66.0/24"
    availability_zone       = "ap-northeast-1c"
    map_public_ip_on_launch = false
}

resource "aws_eip" "iida_hakone_nat_gateway_1" {
    vpc        = true
    depends_on = [aws_internet_gateway.iida_hakone_gateway]
}

resource "aws_nat_gateway" "iida_hakone_nat_gateway_1" {
    allocation_id = aws_eip.iida_hakone_nat_gateway_1.id
    subnet_id     = aws_subnet.iida_hakone_public_1.id
    depends_on    = [aws_internet_gateway.iida_hakone_gateway]
}

resource "aws_route_table" "iida_hakone_private_1" {
    vpc_id = aws_vpc.iida_hakone.id
}

resource "aws_route" "iida_hakone_private_1" {
    route_table_id         = aws_route_table.iida_hakone_private_1.id
    nat_gateway_id         = aws_nat_gateway.iida_hakone_nat_gateway_1.id
    destination_cidr_block = "0.0.0.0/0"
}

resource "aws_route_table_association" "iida_hakone_private_1" {
    subnet_id      = aws_subnet.iida_hakone_private_1.id
    route_table_id = aws_route_table.iida_hakone_private_1.id
}

# security group
resource "aws_security_group" "iida_hakone" {
    name   = "iida-hakone"
    vpc_id = aws_vpc.iida_hakone.id
}

resource "aws_security_group_rule" "iida_hakone_ingress" {
    type        = "ingress"
    from_port   = "80"
    to_port     = "80"
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    security_group_id = aws_security_group.iida_hakone.id
}

resource "aws_security_group_rule" "iida_hakone_egress" {
    type        = "egress"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    security_group_id = aws_security_group.iida_hakone.id
}

# ALB
resource "aws_lb" "iida_hakone" {
    name               = "iida-hakone"
    load_balancer_type = "application"
    internal           = false
    idle_timeout       = 60
    enable_deletion_protection = false

    subnets = [
        aws_subnet.iida_hakone_public_0.id,
        aws_subnet.iida_hakone_public_1.id,
    ]

    # s3にアクセスログ
    #access_logs {
    #    bucket  = aws_s3_bucket.alb_log.id
    #    enabled = true
    #}

    security_groups = [
        aws_security_group.iida_hakone.id,
    ]

}

resource aws_lb_listener "http" {
    load_balancer_arn = aws_lb.iida_hakone.arn
    port     = "80"
    protocol = "HTTP"

    default_action {
        type = "fixed-response"

        fixed_response {
            content_type = "text/plain"
            message_body = "This is http"
            status_code  = "200"
        }
    }
}

resource "aws_lb_target_group" "iida_hakone" {
    name        = "iida-hakone"
    vpc_id      = aws_vpc.iida_hakone.id
    target_type = "ip"
    port        = 80
    protocol    = "HTTP"
    deregistration_delay = 300

    health_check {
        path = "/"
        healthy_threshold   = 5
        unhealthy_threshold = 2
        timeout  = 5
        interval = 30
        matcher  = 200
        port     = "traffic-port"
        protocol = "HTTP"
    }

    depends_on = [aws_lb.iida_hakone]
}

resource "aws_lb_listener_rule" "iida_hakone" {
    listener_arn = aws_lb_listener.http.arn
    priority     = 100

    action {
        type             = "forward"
        target_group_arn = aws_lb_target_group.iida_hakone.arn
    }

    condition {
        field  = "path-pattern"
        values = ["/*"]
    }
}

output "alb_dns_name" {
    value = aws_lb.iida_hakone.dns_name
}

# ECS

resource "aws_ecs_cluster" "iida_hakone" {
    name = "iida_hakone"
}

resource "aws_ecs_task_definition" "iida_hakone" {
    family = "iida_hakone"
    cpu    = "256"
    memory = "512"
    network_mode = "awsvpc"
    requires_compatibilities = ["FARGATE"]
    container_definitions = file("./container_definitions.json")
    execution_role_arn    = module.hakone_iida_ecr_role.iam_role_arn
}

resource "aws_ecs_service" "iida_hakone" {
    name             = "iida-hakone"
    cluster          = aws_ecs_cluster.iida_hakone.arn
    task_definition  = aws_ecs_task_definition.iida_hakone.arn
    desired_count    = 2
    launch_type      = "FARGATE"
    platform_version = "1.3.0"
    health_check_grace_period_seconds = 60

    network_configuration {
        assign_public_ip = false
        security_groups  = [aws_security_group.iida_hakone.id]

        subnets = [
            aws_subnet.iida_hakone_private_0.id,
            aws_subnet.iida_hakone_private_1.id,
        ]
    }

    load_balancer {
        target_group_arn = aws_lb_target_group.iida_hakone.arn
        container_name   = "iida_hakone"
        container_port   = 80
    }

    lifecycle {
        ignore_changes = [task_definition]
    }
}

## IAM ROLE
data "aws_iam_policy" "iida_hakone_ecs_task_execution" {
    arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

data "aws_iam_policy_document" "iida_hakone_ecs_task_execution" {
    source_json = data.aws_iam_policy.iida_hakone_ecs_task_execution.policy

    statement {
        effect    = "Allow"
        actions   = [
            "ssm:GetParameters",
            "kms:Decrypt",
        ]
        resources = ["*"]
    }
}

module "hakone_iida_ecr_role" {
    source = "./iam_role"
    name   = "iida_hakone_ecs_task_execution"
    identifier = "ecs-tasks.amazonaws.com"
    policy = data.aws_iam_policy_document.iida_hakone_ecs_task_execution.json
}

# cloud watch
resource "aws_cloudwatch_log_group" "iida_hakone_ecs" {
    name = "/iida_hakone_ecs/"
    retention_in_days = 1
}

# ECR
resource "aws_ecr_repository" "iida_hakone" {
    name = "iida_hakone"
}

resource "aws_ecr_lifecycle_policy" "iida_hakone" {
    repository = aws_ecr_repository.iida_hakone.name

    policy = <<EOF
    {
        "rules": [
            {
                "rulePriority": 1,
                "description": "Keep last 30 release tagged images",
                "selection": {
                    "tagStatus": "tagged",
                    "tagPrefixList": ["release"],
                    "countType": "imageCountMoreThan",
                    "countNumber": 3
                },
                "action": {
                    "type": "expire"
                }
            }
        ]
    }
EOF
}

output "ecr_name" {
    value = aws_ecr_lifecycle_policy.iida_hakone
}