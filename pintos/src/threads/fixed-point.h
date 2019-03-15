#define p 17
#define q 14
#define f (1 << q)

#define convert_n_to_fixed(n) (n)*(f)
#define convert_x_to_int_zero(x) (x)/(f)
#define convert_x_to_int_near(x) (((x)>=0) ? (((x)+(f)/2)/(f)) : (((x)-(f)/2)/(f)))
#define add_x_y(x,y) (x)+(y)
#define sub_x_y(x,y) (x)-(y)
#define add_x_n(x,n) (x)+(n)*(f)
#define sub_x_n(x,n) (x)-(n)*(f)
#define mul_x_y(x,y) ((int64_t)(x))*(y)/(f)
#define mul_x_n(x,n) (x)*(n)
#define div_x_y(x,y) ((int64_t)(x))*(f)/(y)
#define div_x_n(x,n) (x)/(n)

#define div_n_m(n,m) div_x_n(convert_n_to_fixed((n)),(m))
#define mul_n_m(n,m) mul_x_n(convert_n_to_fixed((n)),(m))
