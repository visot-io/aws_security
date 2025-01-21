import { useState } from 'react'
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { CloudFrontAnalysis } from './components/CloudFrontAnalysis'
import { Cloud, Database, Shield } from "lucide-react"

type AWSService = 'cloudfront' | 's3' | null

function App() {
  const [selectedService, setSelectedService] = useState<AWSService>(null)

  const services = [
    {
      id: 'cloudfront',
      name: 'CloudFront',
      icon: Cloud,
      description: 'Analyze CloudFront distribution security settings'
    },
    {
      id: 's3',
      name: 'S3',
      icon: Database,
      description: 'Coming soon: S3 bucket security analysis'
    }
  ]

  return (
    <div className="container mx-auto py-8">
      {!selectedService ? (
        <>
          <div className="flex items-center mb-8">
            <Shield className="h-8 w-8 mr-3" />
            <h1 className="text-3xl font-bold">AWS Controls</h1>
          </div>
          <div className="grid md:grid-cols-2 gap-6">
            {services.map((service) => (
              <Card 
                key={service.id} 
                className={`cursor-pointer transition-all hover:shadow-lg ${
                  service.id === 's3' ? 'opacity-50' : ''
                }`}
                onClick={() => service.id !== 's3' && setSelectedService(service.id as AWSService)}
              >
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <service.icon className="h-6 w-6" />
                    {service.name}
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="text-gray-600">{service.description}</p>
                </CardContent>
              </Card>
            ))}
          </div>
        </>
      ) : (
        <div>
          <Button 
            variant="ghost" 
            className="mb-4"
            onClick={() => setSelectedService(null)}
          >
            ← Back to Services
          </Button>
          {selectedService === 'cloudfront' && <CloudFrontAnalysis />}
        </div>
      )}
    </div>
  )
}

export default App
