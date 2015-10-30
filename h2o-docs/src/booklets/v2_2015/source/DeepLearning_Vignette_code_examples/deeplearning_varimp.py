# Train a Deep Learning model and validate on a test set
# and save the variable importances
model_vi = H2ODeepLearningEstimator(        
        distribution="multinomial",
        activation="RectifierWithDropout", 
        hidden=[200,200,200], 
        input_dropout_ratio=0.2, 
        sparse=True,
        l1=1e-5, 
        epochs=10,
        variable_importances=True)  #added

model_vi.train(
        x=x, 
        y=y, 
        training_frame=train, 
        validation_frame=test)

# Retrieve the variable importance
model_vi.varimp()