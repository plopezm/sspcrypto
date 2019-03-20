package sspcrypto

import (
	"testing"
)

func TestGeneratePrime(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{
			name: "Number generated is prime 1",
			want: true,
		},
		{
			name: "Number generated is prime 2",
			want: true,
		},
		{
			name: "Number generated is prime 3",
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MillerRabin(int64(GeneratePrime()), 5); got != tt.want {
				t.Errorf("GeneratePrime() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMillerRabin(t *testing.T) {
	type args struct {
		n      int64
		trials int64
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Is not prime 22",
			args: args{
				trials: 5,
				n:      22,
			},
			want: false,
		},
		{
			name: "Is not prime 72314",
			args: args{
				trials: 5,
				n:      72314,
			},
			want: false,
		},
		{
			name: "Is prime 72313",
			args: args{
				trials: 5,
				n:      72313,
			},
			want: true,
		},
		{
			name: "Is prime 44987",
			args: args{
				trials: 5,
				n:      44987,
			},
			want: true,
		},
		{
			name: "Is prime 85159",
			args: args{
				trials: 5,
				n:      85159,
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MillerRabin(tt.args.n, tt.args.trials); got != tt.want {
				t.Errorf("MillerRabin() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestXpowYmodN(t *testing.T) {
	type args struct {
		x int64
		y int64
		N int64
	}
	tests := []struct {
		name string
		args args
		want int64
	}{
		{
			name: "X^YmodN 1",
			args: args{
				x: 31,
				y: 64,
				N: 1024,
			},
			want: 1,
		},
		{
			name: "X^YmodN 2",
			args: args{
				x: 165,
				y: 654,
				N: 1024,
			},
			want: 937,
		},
		{
			name: "X^YmodN 3",
			args: args{
				x: 16512,
				y: 65412,
				N: 102442,
			},
			want: 88430,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := XpowYmodN(tt.args.x, tt.args.y, tt.args.N); got != tt.want {
				t.Errorf("XpowYmodN() = %v, want %v", got, tt.want)
			}
		})
	}
}
