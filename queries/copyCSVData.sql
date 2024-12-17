COPY pizzas (pizza_id, pizza_type_id, size, price)
FROM 'C:\temp\pizza_sales\pizzas.csv'
DELIMITER ',' 
CSV HEADER;
